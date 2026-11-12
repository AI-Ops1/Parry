const { execFile } = require('child_process');
function backupDir(folder) {
  execFile('tar', ['-czf', 'backup.tar.gz', folder]);
}
