const { init: libInit } = require("./lib");
const fs = require("fs");

module.exports.init = async () => {
  return libInit((i) => {
    const buf = fs.readFileSync("./lib.wasm");
    return WebAssembly.instantiate(new Uint8Array(buf), i);
  });
};
