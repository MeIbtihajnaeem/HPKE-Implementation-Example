function ToHexString(byteArray) {
    return Buffer.from(byteArray).toString('hex');

  }
  
  module.exports = { ToHexString };
  