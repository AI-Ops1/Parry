const { exec } = require('child_process');
function backupDir(folder) {
  exec('tar -czf backup.tar.gz ' + folder);
}
