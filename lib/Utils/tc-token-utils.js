const { } = require('../Types');
const { } = require('../WABinary');

/**
 * @typedef {Object} TcTokenParams
 * @property {string} jid
 * @property {Array} [baseContent]
 * @property {{ keys: any }} authState
 */

/**
 * @param {TcTokenParams} param0
 * @returns {Promise<Array|undefined>}
 */
async function buildTcTokenFromJid({
    authState,
    jid,
    baseContent = []
}) {
    try {
        const tcTokenData = await authState.keys.get('tctoken', [jid]);
        const tcTokenBuffer = tcTokenData?.[jid]?.token;

        if (!tcTokenBuffer)
            return baseContent.length > 0 ? baseContent : undefined;

        baseContent.push({
            tag: 'tctoken',
            attrs: {},
            content: tcTokenBuffer
        });

        return baseContent;
    } catch (error) {
        return baseContent.length > 0 ? baseContent : undefined;
    }
}

module.exports = {
    buildTcTokenFromJid
};
