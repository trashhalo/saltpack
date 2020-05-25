const { Go, global } = require("./wasm_exec.js");

const unwrap = (result) => {
  if (!Array.isArray(result) || result.length != 2) {
    throw new Error("can only unrap array of len 2");
  }

  const [res, err] = result;
  if (err != null) {
    throw err;
  }
  return res;
};

module.exports.init = async (wasm) => {
  const go = new Go();
  const result = await wasm(go.importObject);
  go.run(result.instance);
  return {
    keyGen(...args) {
      return unwrap(global.keyGen(...args));
    },
    signValue(...args) {
      return unwrap(global.signValue(...args));
    },
    verifyValue(...args) {
      return unwrap(global.verifyValue(...args));
    },
  };
};
