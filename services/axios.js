const axios = require('axios');
const { version } = require('../package.json');

axios.defaults.headers.common = {
	'User-Agent': `Mozilla/5.0 (compatible; UFW-SpamVerify-Reporter/${version}; +https://github.com/sefinek/UFW-SpamVerify-Reporter)`,
	'Accept': 'application/json',
	'Cache-Control': 'no-cache',
	'Connection': 'keep-alive',
};

axios.defaults.timeout = 30000;

module.exports = axios;