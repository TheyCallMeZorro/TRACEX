/**
 * =========================================================
 * TRACEX - LOG ANALYZER
 * =========================================================
 *
 * Responsible for:
 * - Calculating log statistics
 * - Counting log levels
 * - Counting events
 * - Finding unique IP addresses
 * - Finding unique users
 * - Tracking failed/successful logins
 * - Building timeline data
 * - Ranking IPs and users
 * - Preparing data for dashboard charts
 *
 * Input:
 * Array of normalized log entries from parser.js
 *
 * Output:
 * Structured analysis result
 * =========================================================
 */

const TraceXAnalyzer = (() => {

    "use strict";


    /* =====================================================
       MAIN ANALYSIS
    ===================================================== */

    function analyze(entries = []) {

        if (!Array.isArray(entries)) {
            throw new Error("Analyzer expects an array of log entries.");
        }


        const logs = entries.filter(isValidEntry);


        const result = {

            totalLogs: logs.length,

            uniqueIPs: 0,

            totalUsers: 0,

            failedLogins: 0,

            successfulLogins: 0,

            suspiciousEvents: 0,

            bruteForceAlerts: 0,

            levels: {},

            events: {},

            ips: {},

            users: {},

            timeline: {},

            failedLoginIPs: {},

            failedLoginUsers: {},

            suspiciousLogs: [],

            failedLoginEntries: [],

            loginSuccessEntries: [],

            recentLogs: [],

            topIPs: [],

            topUsers: [],

            dateRange: {

                earliest: null,

                latest: null

            }

        };


        if (logs.length === 0) {
            return result;
        }


        /* -------------------------------------------------
           Process every log entry
        ------------------------------------------------- */

        logs.forEach(log => {

            const level =
                normalizeLevel(log.level);


            const event =
                String(
                    log.event || "General Activity"
                ).trim();


            const ip =
                String(
                    log.ip || ""
                ).trim();


            const username =
                String(
                    log.username || ""
                ).trim();


            /* ---------------------------------------------
               Level Statistics
            --------------------------------------------- */

            result.levels[level] =
                (result.levels[level] || 0) + 1;


            /* ---------------------------------------------
               Event Statistics
            --------------------------------------------- */

            result.events[event] =
                (result.events[event] || 0) + 1;


            /* ---------------------------------------------
               IP Statistics
            --------------------------------------------- */

            if (ip) {

                if (!result.ips[ip]) {

                    result.ips[ip] = {

                        ip,

                        count: 0,

                        failedLogins: 0,

                        successfulLogins: 0,

                        users: {},

                        events: {}

                    };

                }


                result.ips[ip].count++;


                if (username) {

                    result.ips[ip].users[username] =
                        (result.ips[ip].users[username] || 0) + 1;

                }


                result.ips[ip].events[event] =
                    (result.ips[ip].events[event] || 0) + 1;

            }


            /* ---------------------------------------------
               User Statistics
            --------------------------------------------- */

            if (username) {

                if (!result.users[username]) {

                    result.users[username] = {

                        username,

                        count: 0,

                        failedLogins: 0,

                        successfulLogins: 0,

                        ips: {},

                        events: {}

                    };

                }


                result.users[username].count++;


                if (ip) {

                    result.users[username].ips[ip] =
                        (result.users[username].ips[ip] || 0) + 1;

                }


                result.users[username].events[event] =
                    (result.users[username].events[event] || 0) + 1;

            }


            /* ---------------------------------------------
               Login Detection
            --------------------------------------------- */

            if (isFailedLogin(log)) {

                result.failedLogins++;


                result.failedLoginEntries.push(log);


                if (ip) {

                    result.failedLoginIPs[ip] =
                        (result.failedLoginIPs[ip] || 0) + 1;


                    if (result.ips[ip]) {
                        result.ips[ip].failedLogins++;
                    }

                }


                if (username) {

                    result.failedLoginUsers[username] =
                        (result.failedLoginUsers[username] || 0) + 1;


                    if (result.users[username]) {
                        result.users[username].failedLogins++;
                    }

                }

            }


            if (isSuccessfulLogin(log)) {

                result.successfulLogins++;


                result.loginSuccessEntries.push(log);


                if (ip && result.ips[ip]) {
                    result.ips[ip].successfulLogins++;
                }


                if (username && result.users[username]) {
                    result.users[username].successfulLogins++;
                }

            }


            /* ---------------------------------------------
               Suspicious Activity
            --------------------------------------------- */

            if (isSuspicious(log)) {

                result.suspiciousEvents++;

                result.suspiciousLogs.push(log);

            }


            /* ---------------------------------------------
               Timeline
            --------------------------------------------- */

            const timeKey =
                getTimelineKey(log.timestamp);


            if (timeKey) {

                result.timeline[timeKey] =
                    (result.timeline[timeKey] || 0) + 1;

            }


            /* ---------------------------------------------
               Date Range
            --------------------------------------------- */

            updateDateRange(
                result.dateRange,
                log.timestamp
            );

        });


        /* -------------------------------------------------
           Finalize Counters
        ------------------------------------------------- */

        result.uniqueIPs =
            Object.keys(result.ips).length;


        result.totalUsers =
            Object.keys(result.users).length;


        result.topIPs =
            buildTopIPs(result.ips);


        result.topUsers =
            buildTopUsers(result.users);


        result.recentLogs =
            [...logs]
                .reverse()
                .slice(0, 10);


        return result;

    }


    /* =====================================================
       VALIDATION
    ===================================================== */

    function isValidEntry(entry) {

        return (
            entry &&
            typeof entry === "object"
        );

    }


    /* =====================================================
       LEVEL NORMALIZATION
    ===================================================== */

    function normalizeLevel(level) {

        const value =
            String(level || "INFO")
                .trim()
                .toUpperCase();


        if (value === "WARN") {
            return "WARNING";
        }


        if (
            value === "ALERT" ||
            value === "EMERGENCY"
        ) {
            return "CRITICAL";
        }


        return value || "INFO";

    }


    /* =====================================================
       LOGIN DETECTION
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


        if (event === "failed login") {
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


    function isSuccessfulLogin(log) {

        const event =
            String(
                log.event || ""
            ).toLowerCase();


        const message =
            String(
                log.message || ""
            ).toLowerCase();


        if (event === "successful login") {
            return true;
        }


        return (

            message.includes("successful login") ||

            message.includes("login successful") ||

            message.includes("authenticated successfully") ||

            message.includes("authentication successful") ||

            message.includes("logged in")

        );

    }


    /* =====================================================
       SUSPICIOUS ACTIVITY
    ===================================================== */

    function isSuspicious(log) {

        const level =
            normalizeLevel(log.level);


        const event =
            String(
                log.event || ""
            ).toLowerCase();


        const message =
            String(
                log.message || ""
            ).toLowerCase();


        /* High severity */

        if (
            level === "CRITICAL" ||
            level === "ALERT" ||
            level === "EMERGENCY"
        ) {
            return true;
        }


        /* Dangerous events */

        const suspiciousEvents = [

            "failed login",

            "permission change",

            "command execution",

            "network activity"

        ];


        if (
            suspiciousEvents.some(
                suspiciousEvent =>
                    event.includes(suspiciousEvent)
            )
        ) {

            return true;

        }


        /* Suspicious keywords */

        const suspiciousKeywords = [

            "brute force",

            "privilege escalation",

            "unauthorized",

            "malware",

            "attack",

            "exploit",

            "intrusion",

            "blocked",

            "denied",

            "suspicious",

            "sql injection",

            "port scan",

            "scan detected",

            "backdoor",

            "rootkit",

            "ransomware"

        ];


        return suspiciousKeywords.some(
            keyword =>
                message.includes(keyword)
        );

    }


    /* =====================================================
       TIMELINE
    ===================================================== */

    function getTimelineKey(timestamp) {

        if (!timestamp) {
            return "";
        }


        const parsed =
            parseTimestamp(timestamp);


        if (!parsed) {
            return String(timestamp);
        }


        return formatTimelineKey(parsed);

    }


    function parseTimestamp(timestamp) {

        const raw =
            String(timestamp || "").trim();


        if (!raw) {
            return null;
        }


        /* ISO / standard date */

        const direct =
            new Date(raw);


        if (!Number.isNaN(direct.getTime())) {
            return direct;
        }


        /* DD/MM/YYYY HH:mm:ss */

        const slashMatch =
            raw.match(
                /^(\d{2})\/(\d{2})\/(\d{4})\s+(\d{2}):(\d{2}):(\d{2})$/
            );


        if (slashMatch) {

            const [
                ,
                day,
                month,
                year,
                hour,
                minute,
                second
            ] = slashMatch;


            return new Date(
                Number(year),
                Number(month) - 1,
                Number(day),
                Number(hour),
                Number(minute),
                Number(second)
            );

        }


        /* DD-MM-YYYY HH:mm:ss */

        const dashMatch =
            raw.match(
                /^(\d{2})-(\d{2})-(\d{4})\s+(\d{2}):(\d{2}):(\d{2})$/
            );


        if (dashMatch) {

            const [
                ,
                day,
                month,
                year,
                hour,
                minute,
                second
            ] = dashMatch;


            return new Date(
                Number(year),
                Number(month) - 1,
                Number(day),
                Number(hour),
                Number(minute),
                Number(second)
            );

        }


        /* Time-only logs */

        const timeMatch =
            raw.match(
                /^(\d{2}):(\d{2}):(\d{2})$/
            );


        if (timeMatch) {

            const now =
                new Date();


            now.setHours(
                Number(timeMatch[1]),
                Number(timeMatch[2]),
                Number(timeMatch[3]),
                0
            );


            return now;

        }


        return null;

    }


    function formatTimelineKey(date) {

        const year =
            date.getFullYear();


        const month =
            String(
                date.getMonth() + 1
            ).padStart(2, "0");


        const day =
            String(
                date.getDate()
            ).padStart(2, "0");


        return `${year}-${month}-${day}`;

    }


    /* =====================================================
       DATE RANGE
    ===================================================== */

    function updateDateRange(
        dateRange,
        timestamp
    ) {

        const date =
            parseTimestamp(timestamp);


        if (!date) {
            return;
        }


        if (
            !dateRange.earliest ||
            date < dateRange.earliest
        ) {

            dateRange.earliest =
                date;

        }


        if (
            !dateRange.latest ||
            date > dateRange.latest
        ) {

            dateRange.latest =
                date;

        }

    }


    /* =====================================================
       TOP IPs
    ===================================================== */

    function buildTopIPs(ipData) {

        return Object.values(ipData)

            .sort(
                (a, b) =>
                    b.count - a.count
            )

            .slice(0, 10)

            .map(item => ({

                ip: item.ip,

                count: item.count,

                failedLogins:
                    item.failedLogins,

                successfulLogins:
                    item.successfulLogins,

                userCount:
                    Object.keys(item.users).length

            }));

    }


    /* =====================================================
       TOP USERS
    ===================================================== */

    function buildTopUsers(userData) {

        return Object.values(userData)

            .sort(
                (a, b) =>
                    b.count - a.count
            )

            .slice(0, 10)

            .map(item => ({

                username: item.username,

                count: item.count,

                failedLogins:
                    item.failedLogins,

                successfulLogins:
                    item.successfulLogins,

                ipCount:
                    Object.keys(item.ips).length

            }));

    }


    /* =====================================================
       FILTERING
    ===================================================== */

    function filterLogs(
        entries,
        options = {}
    ) {

        if (!Array.isArray(entries)) {
            return [];
        }


        const {

            query = "",

            level = "all",

            ip = "",

            username = "",

            event = "all",

            startDate = "",

            endDate = ""

        } = options;


        const normalizedQuery =
            String(query)
                .trim()
                .toLowerCase();


        const normalizedIP =
            String(ip)
                .trim()
                .toLowerCase();


        const normalizedUsername =
            String(username)
                .trim()
                .toLowerCase();


        return entries.filter(log => {

            /* Query */

            if (normalizedQuery) {

                const searchableText = [

                    log.timestamp,

                    log.level,

                    log.ip,

                    log.username,

                    log.event,

                    log.message,

                    log.raw

                ]
                    .join(" ")
                    .toLowerCase();


                if (
                    !searchableText.includes(
                        normalizedQuery
                    )
                ) {

                    return false;

                }

            }


            /* Level */

            if (
                level &&
                level !== "all"
            ) {

                if (
                    normalizeLevel(log.level) !==
                    normalizeLevel(level)
                ) {

                    return false;

                }

            }


            /* IP */

            if (normalizedIP) {

                if (
                    !String(
                        log.ip || ""
                    )
                        .toLowerCase()
                        .includes(normalizedIP)
                ) {

                    return false;

                }

            }


            /* Username */

            if (normalizedUsername) {

                if (
                    !String(
                        log.username || ""
                    )
                        .toLowerCase()
                        .includes(normalizedUsername)
                ) {

                    return false;

                }

            }


            /* Event */

            if (
                event &&
                event !== "all"
            ) {

                if (
                    String(log.event || "")
                        .toLowerCase() !==
                    String(event)
                        .toLowerCase()
                ) {

                    return false;

                }

            }


            /* Start Date */

            if (startDate) {

                const logDate =
                    parseTimestamp(log.timestamp);


                const start =
                    new Date(startDate);


                if (
                    logDate &&
                    logDate < start
                ) {

                    return false;

                }

            }


            /* End Date */

            if (endDate) {

                const logDate =
                    parseTimestamp(log.timestamp);


                const end =
                    new Date(endDate);


                end.setHours(
                    23,
                    59,
                    59,
                    999
                );


                if (
                    logDate &&
                    logDate > end
                ) {

                    return false;

                }

            }


            return true;

        });

    }


    /* =====================================================
       TIMELINE ARRAY
    ===================================================== */

    function getTimelineData(entries = []) {

        const timeline = {};


        entries.forEach(log => {

            const key =
                getTimelineKey(log.timestamp);


            if (!key) {
                return;
            }


            timeline[key] =
                (timeline[key] || 0) + 1;

        });


        return Object.entries(timeline)

            .sort(
                ([dateA], [dateB]) =>
                    dateA.localeCompare(dateB)
            )

            .map(
                ([date, count]) => ({
                    date,
                    count
                })
            );

    }


    /* =====================================================
       LEVEL DATA
    ===================================================== */

    function getLevelData(entries = []) {

        const levels = {};


        entries.forEach(log => {

            const level =
                normalizeLevel(log.level);


            levels[level] =
                (levels[level] || 0) + 1;

        });


        return levels;

    }


    /* =====================================================
       EVENT DATA
    ===================================================== */

    function getEventData(entries = []) {

        const events = {};


        entries.forEach(log => {

            const event =
                String(
                    log.event ||
                    "General Activity"
                );


            events[event] =
                (events[event] || 0) + 1;

        });


        return events;

    }


    /* =====================================================
       IP DATA
    ===================================================== */

    function getIPData(entries = []) {

        const ips = {};


        entries.forEach(log => {

            const ip =
                String(
                    log.ip || ""
                ).trim();


            if (!ip) {
                return;
            }


            ips[ip] =
                (ips[ip] || 0) + 1;

        });


        return Object.entries(ips)

            .sort(
                ([, countA], [, countB]) =>
                    countB - countA
            )

            .map(
                ([ip, count]) => ({
                    ip,
                    count
                })
            );

    }


    /* =====================================================
       USER DATA
    ===================================================== */

    function getUserData(entries = []) {

        const users = {};


        entries.forEach(log => {

            const username =
                String(
                    log.username || ""
                ).trim();


            if (!username) {
                return;
            }


            users[username] =
                (users[username] || 0) + 1;

        });


        return Object.entries(users)

            .sort(
                ([, countA], [, countB]) =>
                    countB - countA
            )

            .map(
                ([username, count]) => ({
                    username,
                    count
                })
            );

    }


    /* =====================================================
       FAILED LOGIN DATA
    ===================================================== */

    function getFailedLoginData(entries = []) {

        const failed =
            entries.filter(
                isFailedLogin
            );


        const byIP = {};

        const byUser = {};


        failed.forEach(log => {

            const ip =
                String(
                    log.ip || ""
                ).trim();


            const username =
                String(
                    log.username || ""
                ).trim();


            if (ip) {

                byIP[ip] =
                    (byIP[ip] || 0) + 1;

            }


            if (username) {

                byUser[username] =
                    (byUser[username] || 0) + 1;

            }

        });


        return {

            total: failed.length,

            entries: failed,

            byIP,

            byUser

        };

    }


    /* =====================================================
       RISK CALCULATION
    ===================================================== */

    function calculateIPRisk(data) {

        if (!data) {
            return "low";
        }


        const failed =
            Number(
                data.failedLogins || 0
            );


        const total =
            Number(
                data.count || 0
            );


        if (
            failed >= 15 ||
            total >= 100
        ) {

            return "critical";

        }


        if (
            failed >= 8 ||
            total >= 50
        ) {

            return "high";

        }


        if (
            failed >= 3 ||
            total >= 20
        ) {

            return "medium";

        }


        return "low";

    }


    function calculateUserRisk(data) {

        if (!data) {
            return "low";
        }


        const failed =
            Number(
                data.failedLogins || 0
            );


        const total =
            Number(
                data.count || 0
            );


        if (
            failed >= 15 ||
            total >= 100
        ) {

            return "critical";

        }


        if (
            failed >= 8 ||
            total >= 50
        ) {

            return "high";

        }


        if (
            failed >= 3 ||
            total >= 20
        ) {

            return "medium";

        }


        return "low";

    }


    /* =====================================================
       EXPORT
    ===================================================== */

    return {

        analyze,

        filterLogs,

        getTimelineData,

        getLevelData,

        getEventData,

        getIPData,

        getUserData,

        getFailedLoginData,

        calculateIPRisk,

        calculateUserRisk,

        isFailedLogin,

        isSuccessfulLogin,

        isSuspicious,

        parseTimestamp

    };

})();


/* =========================================================
   GLOBAL ACCESS
========================================================= */

window.TraceXAnalyzer = TraceXAnalyzer;