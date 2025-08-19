//   Copyright 2024-2025 © by Sefinek. All Rights Reserved.
//                     https://sefinek.net

const fs = require('node:fs');
const chokidar = require('chokidar');
const { parseUfwLog } = require('ufw-log-parser');
const banner = require('./scripts/banners/ufw.js');
const { axiosService } = require('./scripts/services/axios.js');
const { reportedIPs, loadReportedIPs, saveReportedIPs, isIPReportedRecently, markIPAsReported } = require('./scripts/services/cache.js');
const { refreshServerIPs, getServerIPs } = require('./scripts/services/ipFetcher.js');
const { repoSlug, repoUrl } = require('./scripts/repo.js');
const isSpecialPurposeIP = require('./scripts/isSpecialPurposeIP.js');
const logger = require('./scripts/logger.js');
const config = require('./config.js');
const { UFW_LOG_FILE, SERVER_ID, EXTENDED_LOGS, AUTO_UPDATE_ENABLED, AUTO_UPDATE_SCHEDULE, DISCORD_WEBHOOK_ENABLED, DISCORD_WEBHOOK_URL } = config.MAIN;

let fileOffset = 0;

const reportIp = async ({ srcIp, dpt = 'N/A', proto = 'N/A', id, timestamp, timestampRaw }, categories, comment) => {
	if (!srcIp) return logger.log('Missing source IP (srcIp)', 3);

	try {
		const { data: res } = await axiosService.post('/report', {
			ip_address: srcIp,
			categories,
			comment,
			timestamp,
		});

		logger.log(`Reported ${srcIp} [${dpt}/${proto}]; Categories: ${categories}; Abuse: ${res.data.threat_score}%; Raw timestamp: ${timestampRaw}; Parsed: ${timestamp}`, 1);
		return true;
	} catch (err) {
		const status = err.response?.status ?? 'unknown';
		logger.log(`Failed to report ${srcIp} [${dpt}/${proto}]; ${err.response?.data ? JSON.stringify(err.response.data) : err.message}`, status === 429 ? 0 : 3);
	}
};

const processLogLine = async (line, test = false) => {
	if (!line.includes('[UFW BLOCK]')) return logger.log(`Ignoring invalid line: ${line}`, 2);

	const data = parseUfwLog(line);
	const { srcIp, proto, dpt } = data;
	if (!srcIp) return logger.log(`Missing SRC in the log line: ${line}`, 3);

	// Check IP
	const ips = getServerIPs();
	if (!Array.isArray(ips)) return logger.log(`For some reason, 'ips' from 'getServerIPs()' is not an array. Received: ${ips}`, 3, true);

	if (ips.includes(srcIp)) return logger.log(`Ignoring own IP address: PROTO=${proto?.toLowerCase()} SRC=${srcIp} DPT=${dpt} ID=${data.id}`, 0, EXTENDED_LOGS);
	if (isSpecialPurposeIP(srcIp)) return logger.log(`Ignoring local IP address: PROTO=${proto?.toLowerCase()} SRC=${srcIp} DPT=${dpt} ID=${data.id}`, 0, EXTENDED_LOGS);
	if (proto === 'UDP') {
		if (EXTENDED_LOGS) logger.log(`Skipping UDP traffic: SRC=${srcIp} DPT=${dpt} ID=${data.id}`);
		return;
	}

	if (test) return data;

	// Report
	if (isIPReportedRecently(srcIp)) {
		const lastReportedTime = reportedIPs.get(srcIp);
		const elapsedTime = Math.floor(Date.now() / 1000 - lastReportedTime);
		const days = Math.floor(elapsedTime / 86400);
		const hours = Math.floor((elapsedTime % 86400) / 3600);
		const minutes = Math.floor((elapsedTime % 3600) / 60);
		const seconds = elapsedTime % 60;
		const timeAgo = [
			days && `${days}d`,
			hours && `${hours}h`,
			minutes && `${minutes}m`,
			(seconds || (!days && !hours && !minutes)) && `${seconds}s`,
		].filter(Boolean).join(' ');

		if (EXTENDED_LOGS) logger.log(`${srcIp} was last reported on ${new Date(lastReportedTime * 1000).toLocaleString()} (${timeAgo} ago)`);
		return;
	}

	const categories = config.DETERMINE_CATEGORIES(data);
	const comment = config.REPORT_COMMENT(data, line);

	if (await reportIp(data, categories, comment)) {
		markIPAsReported(srcIp);
		await saveReportedIPs();
	}
};

(async () => {
	banner();

	// Auto updates
	if (AUTO_UPDATE_ENABLED && AUTO_UPDATE_SCHEDULE && SERVER_ID !== 'development') {
		await require('./scripts/services/updates.js');
	} else {
		await require('./scripts/services/version.js');
	}

	// Fetch IPs
	await refreshServerIPs();

	// Load cache
	await loadReportedIPs();

	// Check UFW_LOG_FILE
	if (!fs.existsSync(UFW_LOG_FILE)) {
		logger.log(`Log file ${UFW_LOG_FILE} does not exist`, 3);
		return;
	}

	// Watch
	fileOffset = fs.statSync(UFW_LOG_FILE).size;
	chokidar.watch(UFW_LOG_FILE, { persistent: true, ignoreInitial: true })
		.on('change', path => {
			const stats = fs.statSync(path);
			if (stats.size < fileOffset) {
				fileOffset = 0;
				logger.log('The file has been truncated, and the offset has been reset');
			}

			fs.createReadStream(path, { start: fileOffset, encoding: 'utf8' }).on('data', chunk => {
				chunk.split('\n').filter(line => line.trim()).forEach(processLogLine);
			}).on('end', () => {
				fileOffset = stats.size;
			});
		});

	// Summaries
	if (DISCORD_WEBHOOK_ENABLED && DISCORD_WEBHOOK_URL) await require('./scripts/services/summaries.js')();

	// Ready
	await logger.webhook(`[${repoSlug}](${repoUrl}) was successfully started!`, 0x59D267);
	logger.log(`Ready! Now monitoring: ${UFW_LOG_FILE}`, 1);
	process.send?.('ready');
})();

module.exports = processLogLine;