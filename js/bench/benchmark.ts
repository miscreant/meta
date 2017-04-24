// Copyright (C) 2016 Dmitry Chestnykh
// MIT License. See LICENSE file for details.

export interface Results {
  iterations: number;
  msPerOp: number;
  opsPerSecond: number;
  bytesPerSecond?: number;
}

declare var process: any;

const getTime = (() => {
  if (typeof performance !== "undefined") {
    return performance.now.bind(performance);
  }
  if (typeof process !== "undefined" && process.hrtime) {
    return () => {
      const [sec, nanosec] = process.hrtime();
      return (sec * 1e9 + nanosec) / 1e6;
    };
  }
  return Date.now.bind(Date);
})();

export function benchmark(fn: () => any, bytes?: number): Results {
  let elapsed = 0;
  let iterations = 0;
  let runsPerIteration = 1;

  // Run once without measuring anything to possibly kick-off JIT.
  fn();

  while (true) {
    let startTime: number;
    let diff: number;
    if (runsPerIteration === 1) {
      // Measure one iteration.
      startTime = getTime();
      fn();
      diff = getTime() - startTime;
    } else {
      // Measure many iterations.
      startTime = getTime();
      for (let i = 0; i < runsPerIteration; i++) {
        fn();
      }
      diff = getTime() - startTime;
    }
    // If diff is too small, double the number of iterations
    // and start over without recording results.
    if (diff < 1) {
      runsPerIteration *= 2;
      continue;
    }

    // Otherwise, record the result.
    elapsed += diff;
    iterations += runsPerIteration;
    if (elapsed > 500 && iterations > runsPerIteration * 2) {
      break;
    }
  }
  // Calculate average time per iteration.
  const avg = elapsed / iterations;
  return {
    iterations,
    msPerOp: avg,
    opsPerSecond: 1000 / avg,
    bytesPerSecond: bytes ? 1000 * (bytes * iterations) / (avg * iterations) : undefined
  };
}

export function benchmarkAsync(fn: (done: () => void) => any,
  doneCallback: (results: Results) => void, bytes?: number) {

  let elapsed = 0;

  function run(todo: number, startTime: number, runDone: (diff: number) => void) {
    fn(() => {
      todo -= 1;
      if (todo > 0) {
        run(todo, startTime, runDone);
        return;
      }
      runDone(getTime() - startTime);
    });
  }

  function next(iterations = 0, runsPerIteration = 1) {
    run(runsPerIteration, getTime(), diff => {
      // If diff is too small, double the number of iterations
      // and start over without recording results.
      if (diff < 1) {
        setTimeout(() => { next(iterations, runsPerIteration * 2); }, 0);
        return;
      }

      // Otherwise, record the result.
      elapsed += diff;
      iterations += runsPerIteration;
      if (elapsed > 500 && iterations > runsPerIteration * 2) {
        // We're done.
        const avg = elapsed / iterations;
        doneCallback({
          iterations,
          msPerOp: avg,
          opsPerSecond: 1000 / avg,
          bytesPerSecond: bytes ? 1000 * (bytes * iterations) / (avg * iterations) : undefined
        });
        return;
      }
      // Continue iterating.
      next(iterations, runsPerIteration);
    });
  }

  // Run once without measuring anything to possibly kick-off JIT
  // and then start benchmarking.
  run(1, getTime(), () => next());
}

export function benchmarkPromise(fn: () => Promise<any>, bytes?: number): Promise<Results> {
  return new Promise(resolve => {
    benchmarkAsync(
      done => fn().then(done),
      results => resolve(results),
      bytes
    );
  });
}


export function report(name: string, results: Results) {
  const ops = results.iterations + " ops";
  const msPerOp = results.msPerOp.toFixed(2) + " ms/op";
  const opsPerSecond = results.opsPerSecond.toFixed(2) + " ops/sec";
  const mibPerSecond = results.bytesPerSecond
    ? (results.bytesPerSecond / 1024 / 1024).toFixed(2) + " MiB/s"
    : "";
  console.log(
    pad(name, 30, true) + " " +
    pad(ops, 20) + " " +
    pad(msPerOp, 20) + " " +
    pad(opsPerSecond, 20) + " " +
    pad(mibPerSecond, 15)
  );
}

function pad(s: string, upto: number, end = false) {
  const padlen = upto - s.length;
  if (padlen <= 0) {
    return s;
  }
  // XXX: in ES2015 we can use " ".repeat(padlen)
  const padding = new Array(padlen + 1).join(" ");
  if (end) {
    return s + padding;
  }
  return padding + s;
}

/**
 * Returns a Uint8Array of the given length containing
 * sequence of bytes 0, 1, 2 ... 255, 0, 1, 2, ...
 *
 * If the start byte is given, the sequence starts from it.
 */
export function byteSeq(length: number, start = 0): Uint8Array {
  const b = new Uint8Array(length);
  for (let i = 0; i < b.length; i++) {
    b[i] = (start + i) & 0xff;
  }
  return b;
}
