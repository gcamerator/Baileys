const { platform, release } = require('os')
const { proto } = require('../../WAProto')

/* ===================== Platform Map ===================== */

const PLATFORM_MAP = {
  aix: 'AIX',
  darwin: 'Mac OS',
  win32: 'Windows',
  android: 'Android',
  freebsd: 'FreeBSD',
  openbsd: 'OpenBSD',
  sunos: 'Solaris',
  linux: undefined,
  haiku: undefined,
  cygwin: undefined,
  netbsd: undefined
}

/* ===================== Browsers ===================== */

const Browsers = {
  ubuntu: (browser) => ['Ubuntu', browser, '22.04.4'],
  macOS: (browser) => ['Mac OS', browser, '14.4.1'],
  baileys: (browser) => ['Baileys', browser, '6.5.0'],
  windows: (browser) => ['Windows', browser, '10.0.22631'],
  android: (browser) => [browser, 'Android', ''],

  /** Appropriate browser based on OS & release */
  appropriate: (browser) => [
    PLATFORM_MAP[platform()] || 'Ubuntu',
    browser,
    release()
  ]
}

/* ===================== Platform ID ===================== */

const getPlatformId = (browser) => {
  const platformType =
    proto.DeviceProps.PlatformType[browser.toUpperCase()]

  // default = CHROME (1)
  return platformType ? platformType.toString() : '1'
}

/* ===================== Exports ===================== */

module.exports = {
  Browsers,
  getPlatformId
}
