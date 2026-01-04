const { Boom } = require('@hapi/boom')
const { createHash } = require('crypto')
const { proto } = require('../../WAProto')
const {
  KEY_BUNDLE_TYPE,
  WA_ADV_ACCOUNT_SIG_PREFIX,
  WA_ADV_DEVICE_SIG_PREFIX,
  WA_ADV_HOSTED_ACCOUNT_SIG_PREFIX
} = require('../Defaults')

const {
  getBinaryNodeChild,
  jidDecode,
  S_WHATSAPP_NET
} = require('../WABinary')

const { Curve, hmacSign } = require('./crypto')
const { encodeBigEndian } = require('./generics')
const { createSignalIdentity } = require('./signal')

/* ===================== Helpers ===================== */

const getUserAgent = (config) => ({
  appVersion: {
    primary: config.version[0],
    secondary: config.version[1],
    tertiary: config.version[2]
  },
  platform: config.browser[1].toLowerCase().includes('android')
    ? proto.ClientPayload.UserAgent.Platform.ANDROID
    : proto.ClientPayload.UserAgent.Platform.WEB,
  releaseChannel: proto.ClientPayload.UserAgent.ReleaseChannel.RELEASE,
  osVersion: '0.1',
  device: 'Desktop',
  osBuildNumber: '0.1',
  localeLanguageIso6391: 'en',
  mnc: '000',
  mcc: '000',
  localeCountryIso31661Alpha2: config.countryCode
})

const PLATFORM_MAP = {
  'Mac OS': proto.ClientPayload.WebInfo.WebSubPlatform.DARWIN,
  Windows: proto.ClientPayload.WebInfo.WebSubPlatform.WIN32
}

const getWebInfo = (config) => {
  let webSubPlatform = proto.ClientPayload.WebInfo.WebSubPlatform.WEB_BROWSER

  if (
    config.syncFullHistory &&
    PLATFORM_MAP[config.browser[0]] &&
    config.browser[1] === 'Desktop'
  ) {
    webSubPlatform = PLATFORM_MAP[config.browser[0]]
  }

  return { webSubPlatform }
}

const getClientPayload = (config) => {
  const payload = {
    connectType: proto.ClientPayload.ConnectType.WIFI_UNKNOWN,
    connectReason: proto.ClientPayload.ConnectReason.USER_ACTIVATED,
    userAgent: getUserAgent(config)
  }

  if (!config.browser[1].toLowerCase().includes('android')) {
    payload.webInfo = getWebInfo(config)
  }

  return payload
}

/* ===================== Exports ===================== */

const generateLoginNode = (userJid, config) => {
  const { user, device } = jidDecode(userJid)

  const payload = {
    ...getClientPayload(config),
    passive: true,
    pull: true,
    username: Number(user),
    device,
    lidDbMigrated: false
  }

  return proto.ClientPayload.fromObject(payload)
}

const getPlatformType = (platform) => {
  const p = platform.toUpperCase()
  if (p === 'ANDROID') {
    return proto.DeviceProps.PlatformType.ANDROID_PHONE
  }

  return (
    proto.DeviceProps.PlatformType[p] ??
    proto.DeviceProps.PlatformType.CHROME
  )
}

const generateRegistrationNode = (
  { registrationId, signedPreKey, signedIdentityKey },
  config
) => {
  const appVersionBuf = createHash('md5')
    .update(config.version.join('.'))
    .digest()

  const companion = {
    os: config.browser[0],
    platformType: getPlatformType(config.browser[1]),
    requireFullSync: config.syncFullHistory,
    historySyncConfig: {
      storageQuotaMb: 10240,
      inlineInitialPayloadInE2EeMsg: true,
      supportCallLogHistory: false,
      supportBotUserAgentChatHistory: true,
      supportCagReactionsAndPolls: true,
      supportBizHostedMsg: true,
      supportRecentSyncChunkMessageCountTuning: true,
      supportHostedGroupMsg: true,
      supportFbidBotChatHistory: true,
      supportMessageAssociation: true,
      supportGroupHistory: false
    },
    version: { primary: 10, secondary: 15, tertiary: 7 }
  }

  const companionProto = proto.DeviceProps.encode(companion).finish()

  const payload = {
    ...getClientPayload(config),
    passive: false,
    pull: false,
    devicePairingData: {
      buildHash: appVersionBuf,
      deviceProps: companionProto,
      eRegid: encodeBigEndian(registrationId),
      eKeytype: KEY_BUNDLE_TYPE,
      eIdent: signedIdentityKey.public,
      eSkeyId: encodeBigEndian(signedPreKey.keyId, 3),
      eSkeyVal: signedPreKey.keyPair.public,
      eSkeySig: signedPreKey.signature
    }
  }

  return proto.ClientPayload.fromObject(payload)
}

const configureSuccessfulPairing = (
  stanza,
  { advSecretKey, signedIdentityKey, signalIdentities }
) => {
  const msgId = stanza.attrs.id
  const pairSuccessNode = getBinaryNodeChild(stanza, 'pair-success')
  const deviceIdentityNode = getBinaryNodeChild(pairSuccessNode, 'device-identity')
  const platformNode = getBinaryNodeChild(pairSuccessNode, 'platform')
  const deviceNode = getBinaryNodeChild(pairSuccessNode, 'device')
  const businessNode = getBinaryNodeChild(pairSuccessNode, 'biz')

  if (!deviceIdentityNode || !deviceNode) {
    throw new Boom('Missing device-identity or device', { data: stanza })
  }

  const bizName = businessNode?.attrs?.name
  const jid = deviceNode.attrs.jid
  const lid = deviceNode.attrs.lid

  const decoded = proto.ADVSignedDeviceIdentityHMAC.decode(deviceIdentityNode.content)
  const { details, hmac, accountType } = decoded

  let prefix = Buffer.alloc(0)
  if (accountType === proto.ADVEncryptionType.HOSTED) {
    prefix = WA_ADV_HOSTED_ACCOUNT_SIG_PREFIX
  }

  const advSign = hmacSign(
    Buffer.concat([prefix, details]),
    Buffer.from(advSecretKey, 'base64')
  )

if (Buffer.compare(hmac, advSign) !== 0) { 
    throw new Boom('Invalid account signature')
}
  const account = proto.ADVSignedDeviceIdentity.decode(details)
  const deviceIdentity = proto.ADVDeviceIdentity.decode(account.details)

  const accountPrefix =
    deviceIdentity.deviceType === proto.ADVEncryptionType.HOSTED
      ? WA_ADV_HOSTED_ACCOUNT_SIG_PREFIX
      : WA_ADV_ACCOUNT_SIG_PREFIX

  const accountMsg = Buffer.concat([
    accountPrefix,
    account.details,
    signedIdentityKey.public
  ])

  if (!Curve.verify(account.accountSignatureKey, accountMsg, account.accountSignature)) {
    throw new Boom('Failed to verify account signature')
  }

  const deviceMsg = Buffer.concat([
    WA_ADV_DEVICE_SIG_PREFIX,
    account.details,
    signedIdentityKey.public,
    account.accountSignatureKey
  ])

  account.deviceSignature = Curve.sign(
    signedIdentityKey.private,
    deviceMsg
  )

  const identity = createSignalIdentity(lid, account.accountSignatureKey)
  const accountEnc = encodeSignedDeviceIdentity(account, false)

  return {
    creds: {
      account,
      me: { id: jid, name: bizName, lid },
      signalIdentities: [...(signalIdentities || []), identity],
      platform: platformNode?.attrs?.name
    },
    reply: {
      tag: 'iq',
      attrs: { to: S_WHATSAPP_NET, type: 'result', id: msgId },
      content: [{
        tag: 'pair-device-sign',
        attrs: {},
        content: [{
          tag: 'device-identity',
          attrs: { 'key-index': deviceIdentity.keyIndex.toString() },
          content: accountEnc
        }]
      }]
    }
  }
}

const encodeSignedDeviceIdentity = (account, includeSignatureKey) => {
  account = { ...account }

  if (!includeSignatureKey || !account.accountSignatureKey?.length) {
    account.accountSignatureKey = null
  }

  return proto.ADVSignedDeviceIdentity.encode(account).finish()
}

/* ===================== module.exports ===================== */

module.exports = {
  generateLoginNode,
  generateRegistrationNode,
  configureSuccessfulPairing,
  encodeSignedDeviceIdentity
}
