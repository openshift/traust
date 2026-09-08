// Jazzer.js fuzz harness template (language: javascript).
//
// Copy to harnesses/<id>/<name>.fuzz.js, set dest inside the target clone
// (so require() resolves), point fuzz() at the pure function under test.
// Run via `make fuzz-<id>` or: npx jazzer <dest-without-.js>
// Crashers land as crash-* files plus a reproducer test.

// const { parse } = require("../lib/parser"); // <- target module

/**
 * @param {Buffer} data
 */
module.exports.fuzz = function (data) {
  const s = data.toString("utf8");
  try {
    // parse(s); // <- call the target function
  } catch (e) {
    // expected parse errors are fine; uncaught type confusion,
    // prototype pollution effects, and hangs are the findings
    if (!(e instanceof SyntaxError || e instanceof RangeError)) throw e;
  }
};
