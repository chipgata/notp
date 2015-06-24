/**
 * Created by thuonglt on 6/23/15.
 */
var _codeLength = 6;
var p = require('phpjs');

exports.createSecret = function createSecret (secretLength) {
  var validChars = _getBase32LookupTable();

  delete validChars[32];
  var secret = '';
  for (var i = 0; i < secretLength; i++) {
    secret += validChars[p.array_rand(validChars)];
  }
  return secret;
}

exports.verifyCode = function verifyCode (secret, code, discrepancy) {
  if(discrepancy == null)
    discrepancy = 1;

  var currentTimeSlice = p.floor(p.time() / 30);

  for (var i = -discrepancy; i <= discrepancy; i++) {
    var calculatedCode = getCode(secret, currentTimeSlice + i);
    //console.log(secret+'-'+calculatedCode+'-'+code);
    if (calculatedCode == code) {
      return true;
    }
  }

  return false;
}

function getCode(secret, timeSlice) {
  var crypto = require('crypto');
  if (timeSlice == null) {
    timeSlice = p.floor(p.time() / 30);
  }

  var secretkey = _base32Decode(secret);
  //hmac = crypto.createHmac(algorithm, secretkey);
  // Pack time into binary string
  var time = p.chr(0) + p.chr(0) + p.chr(0) + p.chr(0) + p.pack('N*', timeSlice);
  //console.log(time, '-'+secretkey);
  // Hash it with users secret key
  var hm = crypto.createHmac('sha1', secretkey).update(time).digest('binary');
  // Use last nipple of result as index/offset

  var offset = p.ord(p.substr(hm, -1)) & 0x0F;


  // grab 4 bytes of the result
  var hashpart = p.substr(hm, offset, 4);


  //var bufferpack = require('bufferpack');

  // Unpak binary value
  var value = unpack('N', hashpart);
  //console.log(value, hashpart, offset, hm)
  value = value[''];
  //console.log(value);
  // Only 32 bits
  value = value & 0x7FFFFFFF;

  var modulo = p.pow(10, _codeLength);
  //console.log(modulo, value);
  return p.str_pad(value % modulo, _codeLength, '0', 'STR_PAD_LEFT');
}

function getQRCodeGoogleUrl(name, secret, issuer) {
  var urlencoded = p.urlencode('otpauth://totp/' + name + '?secret=' + secret + '&issuer=' + issuer);
  return 'https://chart.googleapis.com/chart?chs=200x200&chld=M|0&cht=qr&chl=' + urlencoded + '';
}

function setCodeLength(length) {
  _codeLength = length;
  return _codeLength;
}

function _base32Decode(secret) {

  if (p.empty(secret))
    return '';

  var base32chars = _getBase32LookupTable();
  var base32charsFlipped = p.array_flip(base32chars);

  var paddingCharCount = p.substr_count(secret, base32chars[32]);

  var allowedValues = [6, 4, 3, 1, 0];
  if (!p.in_array(paddingCharCount, allowedValues))
    return false;

  for (var i = 0; i < 4; i++) {
    if (paddingCharCount == allowedValues[i] &&
      p.substr(secret, -(allowedValues[i])) != p.str_repeat(base32chars[32], allowedValues[i]))
      return false;
  }

  var secret = p.str_replace('=', '', secret);

  var secret = p.str_split(secret, 1);

  var binaryString = '';
  for (var i = 0; i < secret.length; i = i + 8) {
    var x = '';
    if (!p.in_array(secret[i], base32chars))
      return false;

    for (var j = 0; j < 8; j++) {
     x += p.str_pad(p.base_convert(base32charsFlipped[secret[i + j]], 10, 2), 5, '0', 'STR_PAD_LEFT');
    }
    var eightBits = p.str_split(x, 8);
    for (var z = 0; z < eightBits.length; z++) {
      binaryString += ( (y = p.chr(p.base_convert(eightBits[z], 2, 10))) || p.ord(y) == 48 ) ? y : "";
    }
  }
  return binaryString;
}

function _base32Encode(secret, padding)
{

  if (p.empty(secret)) return '';
  var base32chars = _getBase32LookupTable();
  var secret = p.str_split(secret);
  var binaryString = "";
  for (var i = 0; i < secret.length; i++) {
    binaryString += p.str_pad(p.base_convert(p.ord(secret[i]), 10, 2), 8, '0', 'STR_PAD_LEFT');
  }
  var fiveBitBinaryArray = p.str_split(binaryString, 5);
  var base32 = "";
  var i = 0;
  while (i < fiveBitBinaryArray.length) {
    base32 += base32chars[p.base_convert(p.str_pad(fiveBitBinaryArray[i], 5, '0'), 2, 10)];
    i++;
  }
  var x = p.strlen(binaryString) % 40;
  if (padding && x != 0) {
    if (x == 8) base32 += p.str_repeat(base32chars[32], 6);
    else if (x == 16) base32 += p.str_repeat(base32chars[32], 4);
    else if (x == 24) base32 += p.str_repeat(base32chars[32], 3);
    else if (x == 32) base32 += base32chars[32];
  }
  return base32;
}


function _getBase32LookupTable()
{
  return [
    'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', //  7
    'I', 'J', 'K', 'L', 'M', 'N', 'O', 'P', // 15
    'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X', // 23
    'Y', 'Z', '2', '3', '4', '5', '6', '7', // 31
    '='  // padding char
  ];
}


//codding by thuonglt001@gmail.com
function unpack(format, data) {
  // http://kevin.vanzonneveld.net
  // +   original by: Tim de Koning (http://www.kingsquare.nl)
  // +      parts by: Jonas Raoni Soares Silva - http://www.jsfromhell.com
  // +      parts by: Joshua Bell - http://cautionsingularityahead.blogspot.nl/
  // +
  // +   bugfixed by: marcuswestin
  // %        note 1: Float decoding by: Jonas Raoni Soares Silva
  // %        note 2: Home: http://www.kingsquare.nl/blog/22-12-2009/13650536
  // %        note 3: Feedback: phpjs-unpack@kingsquare.nl
  // %        note 4: 'machine dependant byte order and size' aren't
  // %        note 5: applicable for JavaScript unpack works as on a 32bit,
  // %        note 6: little endian machine
  // *     example 1: unpack('d', "\u0000\u0000\u0000\u0000\u00008YÀ");
  // *     returns 1: { "": -100.875 }

  var formatPointer = 0, dataPointer = 0, result = {}, instruction = '',
    quantifier = '', label = '', currentData = '', i = 0, j = 0,
    word = '', fbits = 0, ebits = 0, dataByteLength = 0;

  // Used by float decoding - by Joshua Bell
  //http://cautionsingularityahead.blogspot.nl/2010/04/javascript-and-ieee754-redux.html
  var fromIEEE754 = function(bytes, ebits, fbits) {
    // Bytes to bits
    var bits = [];
    for (var i = bytes.length; i; i -= 1) {
      var byte = bytes[i - 1];
      for (var j = 8; j; j -= 1) {
        bits.push(byte % 2 ? 1 : 0); byte = byte >> 1;
      }
    }
    bits.reverse();
    var str = bits.join('');

    // Unpack sign, exponent, fraction
    var bias = (1 << (ebits - 1)) - 1;
    var s = parseInt(str.substring(0, 1), 2) ? -1 : 1;
    var e = parseInt(str.substring(1, 1 + ebits), 2);
    var f = parseInt(str.substring(1 + ebits), 2);

    // Produce number
    if (e === (1 << ebits) - 1) {
      return f !== 0 ? NaN : s * Infinity;
    }
    else if (e > 0) {
      return s * Math.pow(2, e - bias) * (1 + f / Math.pow(2, fbits));
    }
    else if (f !== 0) {
      return s * Math.pow(2, -(bias-1)) * (f / Math.pow(2, fbits));
    }
    else {
      return s * 0;
    }
  }

  while (formatPointer < format.length) {
    instruction = format.charAt(formatPointer);

    // Start reading 'quantifier'
    quantifier = '';
    formatPointer++;
    while ((formatPointer < format.length) &&
    (format.charAt(formatPointer).match(/[\d\*]/) !== null)) {
      quantifier += format.charAt(formatPointer);
      formatPointer++;
    }
    if (quantifier === '') {
      quantifier = '1';
    }


    // Start reading label
    label = '';
    while ((formatPointer < format.length) &&
    (format.charAt(formatPointer) !== '/')) {
      label += format.charAt(formatPointer);
      formatPointer++;
    }
    if (format.charAt(formatPointer) === '/') {
      formatPointer++;
    }

    // Process given instruction
    switch (instruction) {
      case 'a': // NUL-padded string
      case 'A': // SPACE-padded string
        if (quantifier === '*') {
          quantifier = data.length - dataPointer;
        } else {
          quantifier = parseInt(quantifier, 10);
        }
        currentData = data.substr(dataPointer, quantifier);
        dataPointer += quantifier;

        if (instruction === 'a') {
          currentResult = currentData.replace(/\0+$/, '');
        } else {
          currentResult = currentData.replace(/ +$/, '');
        }
        result[label] = currentResult;
        break;

      case 'h': // Hex string, low nibble first
      case 'H': // Hex string, high nibble first
        if (quantifier === '*') {
          quantifier = data.length - dataPointer;
        } else {
          quantifier = parseInt(quantifier, 10);
        }
        currentData = data.substr(dataPointer, quantifier);
        dataPointer += quantifier;

        if (quantifier > currentData.length) {
          throw new Error('Warning: unpack(): Type ' + instruction +
            ': not enough input, need ' + quantifier);
        }

        currentResult = '';
        for (i = 0; i < currentData.length; i++) {
          word = currentData.charCodeAt(i).toString(16);
          if (instruction === 'h') {
            word = word[1] + word[0];
          }
          currentResult += word;
        }
        result[label] = currentResult;
        break;

      case 'c': // signed char
      case 'C': // unsigned c
        if (quantifier === '*') {
          quantifier = data.length - dataPointer;
        } else {
          quantifier = parseInt(quantifier, 10);
        }

        currentData = data.substr(dataPointer, quantifier);
        dataPointer += quantifier;

        for (i = 0; i < currentData.length; i++) {
          currentResult = currentData.charCodeAt(i);
          if ((instruction === 'c') && (currentResult >= 128)) {
            currentResult -= 256;
          }
          result[label + (quantifier > 1 ?
            (i + 1) :
            '')] = currentResult;
        }
        break;

      case 'S': // unsigned short (always 16 bit, machine byte order)
      case 's': // signed short (always 16 bit, machine byte order)
      case 'v': // unsigned short (always 16 bit, little endian byte order)
        if (quantifier === '*') {
          quantifier = (data.length - dataPointer) / 2;
        } else {
          quantifier = parseInt(quantifier, 10);
        }

        currentData = data.substr(dataPointer, quantifier * 2);
        dataPointer += quantifier * 2;

        for (i = 0; i < currentData.length; i += 2) {
          // sum per word;
          currentResult = ((currentData.charCodeAt(i + 1) & 0xFF) << 8) +
            (currentData.charCodeAt(i) & 0xFF);
          if ((instruction === 's') && (currentResult >= 32768)) {
            currentResult -= 65536;
          }
          result[label + (quantifier > 1 ?
            ((i / 2) + 1) :
            '')] = currentResult;
        }
        break;

      case 'n': // unsigned short (always 16 bit, big endian byte order)
        if (quantifier === '*') {
          quantifier = (data.length - dataPointer) / 2;
        } else {
          quantifier = parseInt(quantifier, 10);
        }

        currentData = data.substr(dataPointer, quantifier * 2);
        dataPointer += quantifier * 2;

        for (i = 0; i < currentData.length; i += 2) {
          // sum per word;
          currentResult = ((currentData.charCodeAt(i) & 0xFF) << 8) +
            (currentData.charCodeAt(i + 1) & 0xFF);
          result[label + (quantifier > 1 ?
            ((i / 2) + 1) :
            '')] = currentResult;
        }
        break;

      case 'i': // signed integer (machine dependent size and byte order)
      case 'I': // unsigned integer (machine dependent size & byte order)
      case 'l': // signed long (always 32 bit, machine byte order)
      case 'L': // unsigned long (always 32 bit, machine byte order)
      case 'V': // unsigned long (always 32 bit, little endian byte order)
        if (quantifier === '*') {
          quantifier = (data.length - dataPointer) / 4;
        } else {
          quantifier = parseInt(quantifier, 10);
        }

        currentData = data.substr(dataPointer, quantifier * 4);
        dataPointer += quantifier * 4;

        for (i = 0; i < currentData.length; i += 4) {
          currentResult =
            ((currentData.charCodeAt(i + 3) & 0xFF) << 24) +
            ((currentData.charCodeAt(i + 2) & 0xFF) << 16) +
            ((currentData.charCodeAt(i + 1) & 0xFF) << 8) +
            ((currentData.charCodeAt(i) & 0xFF));
          result[label + (quantifier > 1 ?
            ((i / 4) + 1) :
            '')] = currentResult;
        }

        break;

      case 'N': // unsigned long (always 32 bit, little endian byte order)
        if (quantifier === '*') {
          quantifier = (data.length - dataPointer) / 4;
        } else {
          quantifier = parseInt(quantifier, 10);
        }

        currentData = data.substr(dataPointer, quantifier * 4);
        dataPointer += quantifier * 4;

        for (i = 0; i < currentData.length; i += 4) {
          currentResult =
            ((currentData.charCodeAt(i) & 0xFF) << 24) +
            ((currentData.charCodeAt(i + 1) & 0xFF) << 16) +
            ((currentData.charCodeAt(i + 2) & 0xFF) << 8) +
            ((currentData.charCodeAt(i + 3) & 0xFF));
          result[label + (quantifier > 1 ?
            ((i / 4) + 1) :
            '')] = currentResult;
        }

        break;

      case 'f': //float
      case 'd': //double
        ebits = 8;
        fbits = (instruction === 'f') ? 23 : 52;
        dataByteLength = 4;
        if (instruction === 'd') {
          ebits = 11;
          dataByteLength = 8;
        }

        if (quantifier === '*') {
          quantifier = (data.length - dataPointer) / dataByteLength;
        } else {
          quantifier = parseInt(quantifier, 10);
        }

        currentData = data.substr(dataPointer, quantifier * dataByteLength);
        dataPointer += quantifier * dataByteLength;

        for (i = 0; i < currentData.length; i += dataByteLength) {
          data = currentData.substr(i, dataByteLength);

          bytes = [];
          for (j = data.length - 1; j >= 0; --j) {
            bytes.push(data.charCodeAt(j));
          }
          result[label + (quantifier > 1 ?
            ((i / 4) + 1) :
            '')] = fromIEEE754(bytes, ebits, fbits);
        }

        break;

      case 'x': // NUL byte
      case 'X': // Back up one byte
      case '@': // NUL byte
        if (quantifier === '*') {
          quantifier = data.length - dataPointer;
        } else {
          quantifier = parseInt(quantifier, 10);
        }

        if (quantifier > 0) {
          if (instruction === 'X') {
            dataPointer -= quantifier;
          } else {
            if (instruction === 'x') {
              dataPointer += quantifier;
            } else {
              dataPointer = quantifier;
            }
          }
        }
        break;

      default:
        throw new Error('Warning:  unpack() Type ' + instruction +
          ': unknown format code');
    }
  }
  return result;
}
