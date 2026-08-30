/**
 * =========================================================
 * TRACEX - SECURITY DETECTION ENGINE
 * =========================================================
 *
 * Responsible for:
 * - Detecting brute-force activity
 * - Detecting repeated failed logins
 * - Detecting suspicious IP behavior
 * - Detecting privilege escalation indicators
 * - Detecting scanning activity
 * - Detecting malicious keywords/patterns
 * - Assigning severity and risk levels
 * - Producing security alerts for the UI
 *
 * Input:
 * Array of normalized log entries from parser.js
 *
 * Output:
 * Structured security detection results
 * =========================================================
 */

const TraceXDetector = (() => {

    "use strict";


    /* =====================================================
       CONFIGURATION
    ===================================================== */

    const CONFIG = {

        bruteForce: {
            threshold: 5,
            criticalThreshold: 15,
            windowMinutes: 10
        },

        rapidLogin: {
            threshold: 8,
            windowMinutes: 5
        },

        suspiciousIP: {
            failedLoginThreshold: 5,
            eventThreshold: 50
        },

        scanDetection: {
            threshold: 5,
            windowMinutes: 10
        }

    };


    /* =====================================================
       SUSPICIOUS KEYWORDS
    ===================================================== */

    const SUSPICIOUS_PATTERNS = [

        {
            name: "Privilege Escalation",
            severity: "high",
            patterns: [
                /\bprivilege\s+escalation\b/i,
                /\bprivileged\s+access\b/i,
                /\broot\s+access\b/i,
                /\badmin\s+privileges?\b/i,
                /\belevated\s+privileges?\b/i,
                /\bsudo\b/i,
                /\bsu\s+root\b/i
            ]
        },

        {
            name: "Port Scan",
            severity: "high",
            patterns: [
                /\bport\s+scan\b/i,
                /\bport\s+scanning\b/i,
                /\bnmap\b/i,
                /\bscan\s+detected\b/i,
                /\bnetwork\s+scan\b/i
            ]
        },

        {
            name: "SQL Injection",
            severity: "critical",
            patterns: [
                /\bsql\s+injection\b/i,
                /\bunion\s+select\b/i,
                /\bselect\s+.*\s+from\b/i,
                /\bdrop\s+table\b/i,
                /\bor\s+1\s*=\s*1\b/i,
                /\b'[\s]*or[\s]*'1'[\s]*=[\s]*'1\b/i
            ]
        },

        {
            name: "Command Injection",
            severity: "critical",
            patterns: [
                /\bcommand\s+injection\b/i,
                /;\s*(?:bash|sh|cmd|powershell)\b/i,
                /\|\s*(?:bash|sh|cmd|powershell)\b/i,
                /\bexec(?:ute)?\s*\(/i
            ]
        },

        {
            name: "Malware Indicator",
            severity: "critical",
            patterns: [
                /\bmalware\b/i,
                /\bransomware\b/i,
                /\btrojan\b/i,
                /\bbackdoor\b/i,
                /\brootkit\b/i,
                /\bkeylogger\b/i
            ]
        },

        {
            name: "Unauthorized Access",
            severity: "high",
            patterns: [
                /\bunauthorized\s+access\b/i,
                /\bunauthorized\s+login\b/i,
                /\baccess\s+denied\b/i,
                /\bpermission\s+denied\b/i,
                /\bforbidden\b/i
            ]
        },

        {
            name: "Authentication Attack",
            severity: "medium",
            patterns: [
                /\bbrute\s*[- ]?force\b/i,
                /\bpassword\s+spray(?:ing)?\b/i,
                /\bcredential\s+stuffing\b/i,
                /\bmultiple\s+failed\s+login/i
            ]
        },

        {
            name: "Suspicious Execution",
            severity: "high",
            patterns: [
                /\bsuspicious\s+(?:command|process|execution)\b/i,
                /\bmalicious\s+(?:command|process|file)\b/i,
                /\bshell\s+spawned\b/i,
                /\breverse\s+shell\b/i
            ]
        },

        {
            name: "Configuration Change",
            severity: "medium",
            patterns: [
                /\bsecurity\s+configuration\s+changed\b/i,
                /\bfirewall\s+disabled\b/i,
                /\baudit\s+logging\s+disabled\b/i,
                /\blogging\s+disabled\b/i
            ]
        }

    ];


    /* =====================================================
       MAIN DETECTION FUNCTION
    ===================================================== */

    function analyze(entries = []) {

        if (!Array.isArray(entries)) {
            throw new Error(
                "Detector expects an array of log entries."
            );
        }


        const logs =
            entries.filter(Boolean);


        const result = {

            totalLogs: logs.length,

            suspiciousEvents: [],

            bruteForceAttacks: [],

            suspiciousIPs: [],

            scanAlerts: [],

            privilegeEscalationAlerts: [],

            malwareAlerts: [],

            authenticationAlerts: [],

            severityCounts: {

                low: 0,

                medium: 0,

                high: 0,

                critical: 0

            },

            threatCount: 0,

            status: "clean"

        };


        if (logs.length === 0) {
            return result;
        }


        /* -------------------------------------------------
           Pattern-based detection
        ------------------------------------------------- */

        logs.forEach(log => {

            const detections =
                detectSuspiciousPatterns(log);


            detections.forEach(detection => {

                result.suspiciousEvents.push(
                    detection
                );


                incrementSeverity(
                    result.severityCounts,
                    detection.severity
                );


                routeSpecialDetection(
                    result,
                    detection
                );

            });

        });


        /* -------------------------------------------------
           Brute-force detection
        ------------------------------------------------- */

        const bruteForce =
            detectBruteForce(logs);


        result.bruteForceAttacks =
            bruteForce;


        bruteForce.forEach(alert => {

            addUniqueDetection(
                result.suspiciousEvents,
                alert
            );


            incrementSeverity(
                result.severityCounts,
                alert.severity
            );

        });


        /* -------------------------------------------------
           Suspicious IP detection
        ------------------------------------------------- */

        result.suspiciousIPs =
            detectSuspiciousIPs(logs);


        result.suspiciousIPs.forEach(alert => {

            addUniqueDetection(
                result.suspiciousEvents,
                alert
            );


            incrementSeverity(
                result.severityCounts,
                alert.severity
            );

        });


        /* -------------------------------------------------
           Scan detection
        ------------------------------------------------- */

        result.scanAlerts =
            detectScanning(logs);


        result.scanAlerts.forEach(alert => {

            addUniqueDetection(
                result.suspiciousEvents,
                alert
            );


            incrementSeverity(
                result.severityCounts,
                alert.severity
            );

        });


        /* -------------------------------------------------
           Authentication anomalies
        ------------------------------------------------- */

        result.authenticationAlerts =
            detectAuthenticationAnomalies(logs);


        result.authenticationAlerts.forEach(alert => {

            addUniqueDetection(
                result.suspiciousEvents,
                alert
            );


            incrementSeverity(
                result.severityCounts,
                alert.severity
            );

        });


        /* -------------------------------------------------
           Final summary
        ------------------------------------------------- */

        result.suspiciousEvents =
            deduplicateDetections(
                result.suspiciousEvents
            );


        result.threatCount =
            result.suspiciousEvents.length;


        if (
            result.severityCounts.critical > 0
        ) {

            result.status = "critical";

        } else if (
            result.severityCounts.high > 0
        ) {

            result.status = "high";

        } else if (
            result.severityCounts.medium > 0
        ) {

            result.status = "medium";

        } else if (
            result.severityCounts.low > 0
        ) {

            result.status = "low";

        } else {

            result.status = "clean";

        }


        return result;

    }


    /* =====================================================
       SUSPICIOUS PATTERN DETECTION
    ===================================================== */

    function detectSuspiciousPatterns(log) {

        const detections = [];


        const text = [

            log.event,

            log.message,

            log.raw

        ]
            .filter(Boolean)
            .join(" ");


        if (!text.trim()) {
            return detections;
        }


        SUSPICIOUS_PATTERNS.forEach(rule => {

            const matched =
                rule.patterns.some(
                    pattern =>
                        pattern.test(text)
                );


            if (!matched) {
                return;
            }


            const detection = createDetection({

                type: "pattern",

                name: rule.name,

                severity: rule.severity,

                log,

                description:
                    `Potential ${rule.name.toLowerCase()} activity detected.`

            });


            detections.push(detection);

        });


        return detections;

    }


    /* =====================================================
       BRUTE FORCE DETECTION
    ===================================================== */

    function detectBruteForce(entries) {

        const failedLogins =
            entries.filter(
                isFailedLogin
            );


        if (failedLogins.length === 0) {
            return [];
        }


        const byIP = groupByIP(
            failedLogins
        );


        const attacks = [];


        Object.entries(byIP)
            .forEach(([ip, logs]) => {

                const sorted =
                    sortByTimestamp(logs);


                const windows =
                    findThresholdWindows(
                        sorted,
                        CONFIG.bruteForce.threshold,
                        CONFIG.bruteForce.windowMinutes
                    );


                windows.forEach(window => {

                    const count =
                        window.logs.length;


                    const severity =
                        count >=
                        CONFIG.bruteForce.criticalThreshold
                            ? "critical"
                            : count >= 10
                                ? "high"
                                : "medium";


                    attacks.push(
                        createDetection({

                            type: "brute-force",

                            name:
                                "Brute Force Attack",

                            severity,

                            ip,

                            log:
                                window.logs[
                                    window.logs.length - 1
                                ],

                            count,

                            logs:
                                window.logs,

                            description:
                                `${count} failed login attempts from ${ip} within approximately ${CONFIG.bruteForce.windowMinutes} minutes.`

                        })
                    );

                });

            });


        return deduplicateDetections(
            attacks
        );

    }


    /* =====================================================
       SUSPICIOUS IP DETECTION
    ===================================================== */

    function detectSuspiciousIPs(entries) {

        const byIP = {};


        entries.forEach(log => {

            const ip =
                String(
                    log.ip || ""
                ).trim();


            if (!ip) {
                return;
            }


            if (!byIP[ip]) {

                byIP[ip] = {

                    total: 0,

                    failed: 0,

                    logs: []

                };

            }


            byIP[ip].total++;

            byIP[ip].logs.push(log);


            if (isFailedLogin(log)) {
                byIP[ip].failed++;
            }

        });


        const alerts = [];


        Object.entries(byIP)
            .forEach(([ip, data]) => {

                if (
                    data.failed >=
                    CONFIG.suspiciousIP.failedLoginThreshold
                ) {

                    const severity =
                        data.failed >= 15
                            ? "critical"
                            : data.failed >= 10
                                ? "high"
                                : "medium";


                    alerts.push(
                        createDetection({

                            type: "suspicious-ip",

                            name:
                                "Suspicious IP Activity",

                            severity,

                            ip,

                            log:
                                data.logs[
                                    data.logs.length - 1
                                ],

                            count:
                                data.failed,

                            logs:
                                data.logs,

                            description:
                                `${ip} generated ${data.failed} failed authentication attempts.`

                        })
                    );

                }


                if (
                    data.total >=
                    CONFIG.suspiciousIP.eventThreshold
                ) {

                    alerts.push(
                        createDetection({

                            type: "high-volume-ip",

                            name:
                                "High Volume IP",

                            severity: "medium",

                            ip,

                            log:
                                data.logs[
                                    data.logs.length - 1
                                ],

                            count:
                                data.total,

                            logs:
                                data.logs,

                            description:
                                `${ip} generated ${data.total} log events and may require further investigation.`

                        })
                    );

                }

            });


        return deduplicateDetections(
            alerts
        );

    }


    /* =====================================================
       PORT / NETWORK SCANNING
    ===================================================== */

    function detectScanning(entries) {

        const networkLogs =
            entries.filter(log => {

                const text = [

                    log.event,

                    log.message,

                    log.raw

                ]
                    .filter(Boolean)
                    .join(" ");


                return (

                    /\b(port|network|connection|scan)\b/i
                        .test(text)

                );

            });


        const byIP =
            groupByIP(
                networkLogs
            );


        const alerts = [];


        Object.entries(byIP)
            .forEach(([ip, logs]) => {

                const sorted =
                    sortByTimestamp(logs);


                const windows =
                    findThresholdWindows(
                        sorted,
                        CONFIG.scanDetection.threshold,
                        CONFIG.scanDetection.windowMinutes
                    );


                windows.forEach(window => {

                    const distinctEvents =
                        new Set(
                            window.logs.map(
                                log =>
                                    String(
                                        log.event || ""
                                    ).toLowerCase()
                            )
                        );


                    if (
                        distinctEvents.size <
                        CONFIG.scanDetection.threshold
                    ) {
                        return;
                    }


                    alerts.push(
                        createDetection({

                            type: "scan",

                            name:
                                "Possible Network Scan",

                            severity: "high",

                            ip,

                            log:
                                window.logs[
                                    window.logs.length - 1
                                ],

                            count:
                                window.logs.length,

                            logs:
                                window.logs,

                            description:
                                `${ip} generated multiple network-related events in a short period.`

                        })
                    );

                });

            });


        return deduplicateDetections(
            alerts
        );

    }


    /* =====================================================
       AUTHENTICATION ANOMALIES
    ===================================================== */

    function detectAuthenticationAnomalies(entries) {

        const failed =
            entries.filter(
                isFailedLogin
            );


        if (failed.length === 0) {
            return [];
        }


        const byUser = groupByUser(
            failed
        );


        const alerts = [];


        Object.entries(byUser)
            .forEach(([username, logs]) => {

                if (
                    logs.length <
                    CONFIG.rapidLogin.threshold
                ) {

                    return;

                }


                const sorted =
                    sortByTimestamp(logs);


                const windows =
                    findThresholdWindows(
                        sorted,
                        CONFIG.rapidLogin.threshold,
                        CONFIG.rapidLogin.windowMinutes
                    );


                windows.forEach(window => {

                    const ips =
                        new Set(
                            window.logs
                                .map(
                                    log =>
                                        log.ip
                                )
                                .filter(Boolean)
                        );


                    let description;


                    if (ips.size > 1) {

                        description =
                            `Account ${username} received repeated failed login attempts from ${ips.size} different source IPs.`;

                    } else {

                        description =
                            `Account ${username} received repeated failed login attempts in a short period.`;

                    }


                    alerts.push(
                        createDetection({

                            type:
                                "authentication-anomaly",

                            name:
                                "Authentication Anomaly",

                            severity:
                                ips.size >= 3
                                    ? "high"
                                    : "medium",

                            username,

                            log:
                                window.logs[
                                    window.logs.length - 1
                                ],

                            count:
                                window.logs.length,

                            logs:
                                window.logs,

                            description

                        })
                    );

                });

            });


        return deduplicateDetections(
            alerts
        );

    }


    /* =====================================================
       FAILED LOGIN
    ===================================================== */

    function isFailedLogin(log) {

        const event =
            String(
                log.event || ""
            ).toLowerCase();


        const message =
            String(
                log.message || ""
            ).toLowerCase();


        if (
            event === "failed login"
        ) {

            return true;

        }


        return (

            message.includes("failed login") ||

            message.includes("login failed") ||

            message.includes("authentication failed") ||

            message.includes("authentication failure") ||

            message.includes("invalid password") ||

            message.includes("invalid credentials") ||

            message.includes("access denied") ||

            message.includes("login denied")

        );

    }


    /* =====================================================
       GROUPING
    ===================================================== */

    function groupByIP(entries) {

        const groups = {};


        entries.forEach(log => {

            const ip =
                String(
                    log.ip || "Unknown"
                ).trim();


            if (!groups[ip]) {
                groups[ip] = [];
            }


            groups[ip].push(log);

        });


        return groups;

    }


    function groupByUser(entries) {

        const groups = {};


        entries.forEach(log => {

            const username =
                String(
                    log.username || "Unknown"
                ).trim();


            if (!groups[username]) {
                groups[username] = [];
            }


            groups[username].push(log);

        });


        return groups;

    }


    /* =====================================================
       TIME WINDOW DETECTION
    ===================================================== */

    function findThresholdWindows(
        logs,
        threshold,
        windowMinutes
    ) {

        const windows = [];


        if (
            !Array.isArray(logs) ||
            logs.length < threshold
        ) {

            return windows;

        }


        for (
            let start = 0;
            start <= logs.length - threshold;
            start++
        ) {

            const startDate =
                parseTimestamp(
                    logs[start]?.timestamp
                );


            if (!startDate) {

                const fallbackLogs =
                    logs.slice(
                        start,
                        start + threshold
                    );


                if (
                    fallbackLogs.length >= threshold
                ) {

                    windows.push({

                        logs: fallbackLogs

                    });

                }


                continue;

            }


            const selected = [];


            for (
                let index = start;
                index < logs.length;
                index++
            ) {

                const current =
                    parseTimestamp(
                        logs[index]?.timestamp
                    );


                if (!current) {
                    continue;
                }


                const difference =
                    Math.abs(
                        current.getTime() -
                        startDate.getTime()
                    );


                const minutes =
                    difference /
                    60000;


                if (
                    minutes <=
                    windowMinutes
                ) {

                    selected.push(
                        logs[index]
                    );

                } else {

                    break;

                }

            }


            if (
                selected.length >=
                threshold
            ) {

                windows.push({

                    logs: selected

                });

            }

        }


        return windows;

    }


    /* =====================================================
       TIMESTAMP PARSING
    ===================================================== */

    function parseTimestamp(timestamp) {

        if (!timestamp) {
            return null;
        }


        const raw =
            String(timestamp)
                .trim();


        if (!raw) {
            return null;
        }


        const direct =
            new Date(raw);


        if (
            !Number.isNaN(
                direct.getTime()
            )
        ) {

            return direct;

        }


        const slash =
            raw.match(
                /^(\d{2})\/(\d{2})\/(\d{4})\s+(\d{2}):(\d{2}):(\d{2})$/
            );


        if (slash) {

            return new Date(

                Number(slash[3]),

                Number(slash[2]) - 1,

                Number(slash[1]),

                Number(slash[4]),

                Number(slash[5]),

                Number(slash[6])

            );

        }


        const dash =
            raw.match(
                /^(\d{2})-(\d{2})-(\d{4})\s+(\d{2}):(\d{2}):(\d{2})$/
            );


        if (dash) {

            return new Date(

                Number(dash[3]),

                Number(dash[2]) - 1,

                Number(dash[1]),

                Number(dash[4]),

                Number(dash[5]),

                Number(dash[6])

            );

        }


        return null;

    }


    function sortByTimestamp(entries) {

        return [...entries].sort(
            (a, b) => {

                const dateA =
                    parseTimestamp(
                        a.timestamp
                    );


                const dateB =
                    parseTimestamp(
                        b.timestamp
                    );


                if (!dateA && !dateB) {
                    return 0;
                }


                if (!dateA) {
                    return 1;
                }


                if (!dateB) {
                    return -1;
                }


                return (
                    dateA.getTime() -
                    dateB.getTime()
                );

            }
        );

    }


    /* =====================================================
       DETECTION CREATION
    ===================================================== */

    function createDetection(options = {}) {

        const {

            type = "unknown",

            name = "Security Alert",

            severity = "medium",

            log = null,

            ip = "",

            username = "",

            count = 1,

            logs = [],

            description = ""

        } = options;


        return {

            id:
                createDetectionId(
                    type,
                    ip,
                    username,
                    log
                ),

            type,

            name,

            severity:
                normalizeSeverity(
                    severity
                ),

            ip,

            username,

            count,

            timestamp:
                log?.timestamp || "",

            event:
                log?.event || "",

            message:
                log?.message || "",

            logs,

            description,

            detectedAt:
                new Date().toISOString()

        };

    }


    function createDetectionId(
        type,
        ip,
        username,
        log
    ) {

        return [

            type,

            ip || "unknown-ip",

            username || "unknown-user",

            log?.id || log?.timestamp || Math.random()

        ].join("-");

    }


    /* =====================================================
       SEVERITY
    ===================================================== */

    function normalizeSeverity(severity) {

        const value =
            String(
                severity || "medium"
            )
                .trim()
                .toLowerCase();


        if (
            ["critical", "high", "medium", "low"]
                .includes(value)
        ) {

            return value;

        }


        return "medium";

    }


    function incrementSeverity(
        counters,
        severity
    ) {

        const normalized =
            normalizeSeverity(
                severity
            );


        counters[normalized] =
            (counters[normalized] || 0) + 1;

    }


    /* =====================================================
       SPECIAL DETECTION ROUTING
    ===================================================== */

    function routeSpecialDetection(
        result,
        detection
    ) {

        if (!detection) {
            return;
        }


        switch (detection.name) {

            case "Privilege Escalation":

                result.privilegeEscalationAlerts.push(
                    detection
                );

                break;


            case "Malware Indicator":

                result.malwareAlerts.push(
                    detection
                );

                break;


            case "Authentication Attack":

                result.authenticationAlerts.push(
                    detection
                );

                break;


            default:
                break;

        }

    }


    /* =====================================================
       DEDUPLICATION
    ===================================================== */

    function addUniqueDetection(
        array,
        detection
    ) {

        if (!detection) {
            return;
        }


        const exists =
            array.some(
                existing =>
                    existing.id ===
                    detection.id
            );


        if (!exists) {
            array.push(detection);
        }

    }


    function deduplicateDetections(
        detections
    ) {

        const map =
            new Map();


        detections.forEach(
            detection => {

                if (!detection) {
                    return;
                }


                const key =
                    [
                        detection.type,

                        detection.name,

                        detection.ip,

                        detection.username,

                        detection.timestamp

                    ].join("|");


                const existing =
                    map.get(key);


                if (!existing) {

                    map.set(
                        key,
                        detection
                    );

                    return;

                }


                /* Keep the more severe result */

                const currentRank =
                    severityRank(
                        detection.severity
                    );


                const existingRank =
                    severityRank(
                        existing.severity
                    );


                if (
                    currentRank >
                    existingRank
                ) {

                    map.set(
                        key,
                        detection
                    );

                }

            }
        );


        return Array.from(
            map.values()
        );

    }


    function severityRank(severity) {

        const ranks = {

            low: 1,

            medium: 2,

            high: 3,

            critical: 4

        };


        return (
            ranks[
                normalizeSeverity(
                    severity
                )
            ] || 0
        );

    }


    /* =====================================================
       QUICK HELPERS
    ===================================================== */

    function getThreatSummary(
        detections = []
    ) {

        const summary = {

            total: detections.length,

            low: 0,

            medium: 0,

            high: 0,

            critical: 0

        };


        detections.forEach(
            detection => {

                const severity =
                    normalizeSeverity(
                        detection.severity
                    );


                summary[severity]++;

            }
        );


        return summary;

    }


    function getAlertsBySeverity(
        detections = [],
        severity = "all"
    ) {

        if (
            severity === "all"
        ) {

            return [...detections];

        }


        const normalized =
            normalizeSeverity(
                severity
            );


        return detections.filter(
            detection =>
                normalizeSeverity(
                    detection.severity
                ) === normalized
        );

    }


    function getAlertsByIP(
        detections = [],
        ip = ""
    ) {

        const target =
            String(ip)
                .trim()
                .toLowerCase();


        if (!target) {
            return [];
        }


        return detections.filter(
            detection =>
                String(
                    detection.ip || ""
                )
                    .trim()
                    .toLowerCase() === target
        );

    }


    function getAlertsByUser(
        detections = [],
        username = ""
    ) {

        const target =
            String(username)
                .trim()
                .toLowerCase();


        if (!target) {
            return [];
        }


        return detections.filter(
            detection =>
                String(
                    detection.username || ""
                )
                    .trim()
                    .toLowerCase() === target
        );

    }


    /* =====================================================
       PUBLIC API
    ===================================================== */

    return {

        analyze,

        detectSuspiciousPatterns,

        detectBruteForce,

        detectSuspiciousIPs,

        detectScanning,

        detectAuthenticationAnomalies,

        isFailedLogin,

        getThreatSummary,

        getAlertsBySeverity,

        getAlertsByIP,

        getAlertsByUser,

        normalizeSeverity

    };

})();


/* =========================================================
   GLOBAL ACCESS
========================================================= */

window.TraceXDetector = TraceXDetector;