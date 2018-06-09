const util = require('util');
const exec = util.promisify(require('child_process').exec);

async function ls() {
    const {
        stdout,
        stderr
    } = await exec('sh git.sh').catch(function (reason) {
        console.log("sadly, this failed. - " + reason);
        process.exit(0);
    });
    console.log('stdout:', stdout);
    console.log('stderr:', stderr);
};
ls();