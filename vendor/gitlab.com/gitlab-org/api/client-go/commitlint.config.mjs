export default {
  extends: ['@commitlint/config-conventional'],
  "rules": {
    "body-max-line-length": [0, "always", 100],
    "subject-case": [0, "always", ["sentence-case"]],
    "header-max-length": [2, "always", 200]
  }
};
