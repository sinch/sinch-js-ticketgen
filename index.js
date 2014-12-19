var btoa = require('btoa');
var atob = require('atob');
var hmac = require('crypto-js/hmac-sha256');
var CryptoBase64 = require('crypto-js/enc-base64');
var CryptoUtf8 = require('crypto-js/enc-utf8')

module.exports = function(appKey, appSecret, user, timestamp) {
    var userTicket = {
        'applicationKey': appKey,
        'identity': {'type': 'username', 'endpoint': user['username']},
        'created': timestamp || (new Date()).toISOString(),
        'expiresIn': 86400, //24 hour default expire
    }

    var userTicketJson = JSON.stringify(userTicket).replace(" ", "")
    var userTicketBase64 = btoa(userTicketJson)

    // TicketSignature = Base64 ( HMAC-SHA256 ( ApplicationSecret, UTF8 ( UserTicketJson ) ) )
    var digest = hmac(userTicketJson, CryptoBase64.parse(appSecret));
    var signature = digest.toString(CryptoBase64);

    // UserTicket = TicketData + ":" + TicketSignature
    var signedUserTicket = userTicketBase64 + ':' + signature
    return {'userTicket': signedUserTicket}
}