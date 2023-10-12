class MemoryStore {
  constructor() {
    this.attempts = {};
  }

  incr(key, cb) {
    if (!this.attempts[key]) {
      this.attempts[key] = 1;
    } else {
      this.attempts[key]++;
    }
    cb(null, this.attempts[key]);
  }

  decrement(key) {
    if (this.attempts[key]) {
      this.attempts[key]--;
    }
  }

  resetKey(key) {
    delete this.attempts[key];
  }
}

module.exports = MemoryStore;
