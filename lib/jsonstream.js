/**
 * Streaming reader for Entra ID JSON exports.
 *
 * Accepts either a root array `[ {...}, {...} ]` or a Graph-style object
 * `{ "value": [ {...} ] }` and emits each top-level element of the events array
 * as soon as it is complete, so the whole file never has to sit in memory as a
 * string. A truncated file (export cut off mid-object) naturally yields every
 * complete event before the cut; the partial last one is dropped.
 */

const fs = require('fs');

/**
 * @param {string} filepath
 * @param {(obj: object) => void} onEvent
 * @returns {Promise<{ count: number, truncated: boolean, badObjects: number }>}
 */
function streamEvents(filepath, onEvent) {
  return new Promise((resolve, reject) => {
    const stream = fs.createReadStream(filepath, { encoding: 'utf8', highWaterMark: 1 << 20 });

    let depth = 0;
    let inString = false;
    let escape = false;
    let arrayDepth = -1;   // depth *inside* the events array once found
    let arrayClosed = false;
    let inObj = false;
    let objStart = 0;
    let pending = '';      // object text carried over from previous chunks
    let count = 0;
    let badObjects = 0;

    stream.on('data', chunk => {
      for (let i = 0; i < chunk.length; i++) {
        const c = chunk.charCodeAt(i);

        if (inString) {
          if (escape) escape = false;
          else if (c === 92) escape = true;        // backslash
          else if (c === 34) inString = false;     // "
          continue;
        }

        if (c === 34) {
          inString = true;
        } else if (c === 123 || c === 91) {        // { [
          if (arrayDepth < 0) {
            if (c === 91 && depth <= 1) arrayDepth = depth + 1;
          } else if (c === 123 && depth === arrayDepth && !arrayClosed) {
            inObj = true;
            objStart = i;
            pending = '';
          }
          depth++;
        } else if (c === 125 || c === 93) {        // } ]
          depth--;
          if (c === 125 && inObj && depth === arrayDepth) {
            const text = pending + chunk.slice(objStart, i + 1);
            inObj = false;
            pending = '';
            let obj;
            try { obj = JSON.parse(text); } catch (_) { badObjects++; continue; }
            count++;
            onEvent(obj);
          } else if (c === 93 && arrayDepth >= 0 && depth === arrayDepth - 1) {
            arrayClosed = true;
          }
        }
      }
      if (inObj) {
        pending += chunk.slice(objStart);
        objStart = 0;
      }
    });

    stream.on('end', () => resolve({ count, truncated: arrayDepth >= 0 && !arrayClosed, badObjects }));
    stream.on('error', reject);
  });
}

module.exports = { streamEvents };
