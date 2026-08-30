/**
 * =========================================================
 * TRACEX - LOG PARSER
 * =========================================================
 *
 * Responsible for:
 * - Reading uploaded log files
 * - Detecting the log format
 * - Parsing common log patterns
 * - Extracting timestamps
 * - Extracting log levels
 * - Extracting IP addresses
 * - Extracting usernames
 * - Detecting common event types
 * - Returning normalized log objects
 *
 * No UI code belongs in this file.
 * =========================================================
 */

const TraceXParser = (() => {

    "use strict";


    /* =====================================================
       CONSTANTS
    ===================================================== */

    const LOG_LEVELS = [
        "DEBUG",
        "INFO",
        "NOTICE",
        "WARNING",
        "WARN",
        "ERROR",
        "CRITICAL",
        "ALERT",
        "EMERGENCY"
    ];


    const EVENT_PATTERNS = [
        {
            name: "Failed Login",
            patterns: [
                /failed\s+login/i,
                /login\s+failed/i,
                /authentication\s+failed/i,
                /auth(?:entication)?\s+failure/i,
                /invalid\s+(?:user|username|password|credentials)/i,
                /incorrect\s+(?:password|credentials)/i,
                /login\s+denied/i,
                /access\s+denied/i
            ]
        },

        {
            name: "Successful Login",
            patterns: [
                /successful\s+login/i,
                /login\s+successful/i,
                /authenticated\s+successfully/i,
                /authentication\s+successful/i,
                /logged\s+in/i,
                /user\s+login/i
            ]
        },

        {
            name: "Logout",
            patterns: [
                /\blogout\b/i,
                /\blogged\s+out\b/i,
                /\bsession\s+ended\b/i
            ]
        },

        {
            name: "Connection",
            patterns: [
                /\bconnected\b/i,
                /\bconnection\s+(?:opened|established|accepted)\b/i,
                /\bnew\s+connection\b/i
            ]
        },

        {
            name: "Disconnection",
            patterns: [
                /\bdisconnected\b/i,
                /\bconnection\s+(?:closed|terminated|reset)\b/i
            ]
        },

        {
            name: "File Access",
            patterns: [
                /\bfile\s+(?:accessed|opened|read|written|modified|deleted)\b/i,
                /\baccessed\s+file\b/i,
                /\bfile\s+operation\b/i
            ]
        },

        {
            name: "Process",
            patterns: [
                /\bprocess\s+(?:started|stopped|created|terminated)\b/i,
                /\bprocess\s+id\b/i,
                /\bpid[=:]\s*\d+/i
            ]
        },

        {
            name: "Command Execution",
            patterns: [
                /\bcommand\s+(?:executed|execution|run)\b/i,
                /\bexecut(?:ed|ing)\s+command\b/i,
                /\bexec\b/i
            ]
        },

        {
            name: "Permission Change",
            patterns: [
                /\bpermission\s+(?:changed|modified|updated)\b/i,
                /\bprivilege\s+(?:changed|escalated)\b/i,
                /\baccess\s+rights?\s+(?:changed|modified)\b/i
            ]
        },

        {
            name: "Network Activity",
            patterns: [
                /\binbound\s+connection\b/i,
                /\boutbound\s+connection\b/i,
                /\bnetwork\s+(?:request|activity|traffic)\b/i,
                /\bremote\s+connection\b/i
            ]
        },

        {
            name: "Error",
            patterns: [
                /\berror\b/i,
                /\bexception\b/i,
                /\bfatal\b/i,
                /\bpanic\b/i
            ]
        },

        {
            name: "Warning",
            patterns: [
                /\bwarning\b/i,
                /\bwarn\b/i,
                /\bsuspicious\b/i
            ]
        }
    ];


    /* =====================================================
       PUBLIC API
    ===================================================== */

    function parseFile(file) {

        return new Promise((resolve, reject) => {

            if (!(file instanceof File)) {
                reject(new Error("Invalid file supplied."));
                return;
            }

            const reader = new FileReader();

            reader.onload = event => {

                try {

                    const content = event.target.result;

                    const result = parseContent(
                        content,
                        file.name
                    );

                    resolve(result);

                } catch (error) {

                    reject(error);

                }

            };


            reader.onerror = () => {

                reject(
                    new Error("Unable to read the selected file.")
                );

            };


            reader.readAsText(file);

        });

    }


    function parseContent(content, fileName = "unknown.log") {

        if (typeof content !== "string") {
            throw new Error("Log content must be text.");
        }

        const normalizedContent =
            content.replace(/\r\n/g, "\n")
                   .replace(/\r/g, "\n");

        const lines =
            normalizedContent
                .split("\n")
                .filter(line => line.trim().length > 0);


        if (lines.length === 0) {

            return {
                fileName,
                format: "unknown",
                totalLines: 0,
                entries: []
            };

        }


        const format = detectFormat(lines);

        let entries;


        switch (format) {

            case "csv":
                entries = parseCSV(lines);
                break;

            case "json":
                entries = parseJSON(normalizedContent);
                break;

            case "apache":
                entries = parseApache(lines);
                break;

            case "syslog":
                entries = parseSyslog(lines);
                break;

            case "generic":
            default:
                entries = parseGeneric(lines);
                break;
        }


        entries = entries
            .filter(entry => entry !== null)
            .map((entry, index) => normalizeEntry(
                entry,
                index + 1
            ));


        return {
            fileName,
            format,
            totalLines: lines.length,
            entries
        };

    }


    /* =====================================================
       FORMAT DETECTION
    ===================================================== */

    function detectFormat(lines) {

        const sample =
            lines
                .slice(0, Math.min(lines.length, 10))
                .join("\n");


        const firstLine =
            lines[0].trim();


        /* JSON */

        if (
            firstLine.startsWith("[") ||
            firstLine.startsWith("{")
        ) {

            try {

                JSON.parse(
                    firstLine.startsWith("[")
                        ? firstLine
                        : sample
                );

                return "json";

            } catch {
                /* Continue detection */
            }

        }


        /* CSV */

        if (looksLikeCSV(lines)) {
            return "csv";
        }


        /* Apache / Combined */

        if (
            lines.some(line =>
                /^\S+\s+\S+\s+\S+\s+\[[^\]]+\]\s+".*?"\s+\d{3}\s+\d+/.test(line)
            )
        ) {

            return "apache";

        }


        /* Syslog */

        if (
            lines.some(line =>
                /^(?:[A-Z][a-z]{2}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})/.test(line)
            )
        ) {

            return "syslog";

        }


        return "generic";

    }


    function looksLikeCSV(lines) {

        if (lines.length < 1) {
            return false;
        }


        const first = lines[0];


        if (!first.includes(",")) {
            return false;
        }


        const columns =
            first
                .split(",")
                .map(value => value.trim().toLowerCase());


        const usefulHeaders = [
            "timestamp",
            "time",
            "date",
            "level",
            "severity",
            "ip",
            "ip address",
            "user",
            "username",
            "event",
            "message",
            "log"
        ];


        return columns.some(column =>
            usefulHeaders.includes(column)
        );

    }


    /* =====================================================
       CSV PARSER
    ===================================================== */

    function parseCSV(lines) {

        if (lines.length === 0) {
            return [];
        }


        const headers =
            splitCSVLine(lines[0])
                .map(header =>
                    header.trim()
                        .replace(/^["']|["']$/g, "")
                        .toLowerCase()
                );


        const entries = [];


        for (let index = 1; index < lines.length; index++) {

            const line = lines[index];


            if (!line.trim()) {
                continue;
            }


            const values = splitCSVLine(line);

            const object = {};


            headers.forEach((header, columnIndex) => {

                object[header] =
                    values[columnIndex] !== undefined
                        ? values[columnIndex].trim()
                        : "";

            });


            entries.push({
                raw: line,
                timestamp: firstValue(object, [
                    "timestamp",
                    "time",
                    "datetime",
                    "date"
                ]),
                level: firstValue(object, [
                    "level",
                    "severity",
                    "loglevel",
                    "log_level"
                ]),
                ip: firstValue(object, [
                    "ip",
                    "ip address",
                    "ip_address",
                    "source_ip",
                    "src_ip"
                ]),
                username: firstValue(object, [
                    "user",
                    "username",
                    "account",
                    "account_name"
                ]),
                event: firstValue(object, [
                    "event",
                    "event_type",
                    "type",
                    "action"
                ]),
                message: firstValue(object, [
                    "message",
                    "msg",
                    "description",
                    "log",
                    "details"
                ])
            });

        }


        return entries;

    }


    function splitCSVLine(line) {

        const values = [];

        let value = "";
        let insideQuotes = false;


        for (let i = 0; i < line.length; i++) {

            const char = line[i];

            if (char === '"') {

                if (
                    insideQuotes &&
                    line[i + 1] === '"'
                ) {

                    value += '"';
                    i++;

                } else {

                    insideQuotes = !insideQuotes;

                }

                continue;

            }


            if (char === "," && !insideQuotes) {

                values.push(value);
                value = "";

                continue;

            }


            value += char;

        }


        values.push(value);

        return values;

    }


    /* =====================================================
       JSON PARSER
    ===================================================== */

    function parseJSON(content) {

        let data;


        try {

            data = JSON.parse(content);

        } catch {

            const lines =
                content
                    .split("\n")
                    .filter(line => line.trim());


            const objects = [];


            for (const line of lines) {

                try {
                    objects.push(JSON.parse(line));
                } catch {
                    /* Ignore malformed JSON lines */
                }

            }


            data = objects;

        }


        if (!Array.isArray(data)) {
            data = [data];
        }


        return data.map(object => {

            if (
                typeof object !== "object" ||
                object === null
            ) {

                return null;

            }


            return {
                raw: JSON.stringify(object),
                timestamp: firstValue(object, [
                    "timestamp",
                    "time",
                    "datetime",
                    "date",
                    "@timestamp"
                ]),
                level: firstValue(object, [
                    "level",
                    "severity",
                    "log_level",
                    "loglevel"
                ]),
                ip: firstValue(object, [
                    "ip",
                    "ip_address",
                    "source_ip",
                    "src_ip",
                    "client_ip",
                    "remote_ip"
                ]),
                username: firstValue(object, [
                    "user",
                    "username",
                    "account",
                    "account_name"
                ]),
                event: firstValue(object, [
                    "event",
                    "event_type",
                    "type",
                    "action"
                ]),
                message: firstValue(object, [
                    "message",
                    "msg",
                    "description",
                    "details"
                ])
            };

        });

    }


    /* =====================================================
       APACHE LOG PARSER
    ===================================================== */

    function parseApache(lines) {

        const entries = [];


        const pattern =
            /^(\S+)\s+(\S+)\s+(\S+)\s+\[([^\]]+)\]\s+"([^"]*)"\s+(\d{3})\s+(\S+)/;


        lines.forEach(line => {

            const match = line.match(pattern);


            if (!match) {

                entries.push({
                    raw: line,
                    message: line
                });

                return;

            }


            const [
                ,
                ip,
                identity,
                user,
                timestamp,
                request,
                status,
                size
            ] = match;


            let level = "INFO";


            const numericStatus =
                Number(status);


            if (numericStatus >= 500) {
                level = "ERROR";
            } else if (numericStatus >= 400) {
                level = "WARNING";
            }


            entries.push({

                raw: line,

                timestamp,

                level,

                ip,

                username:
                    user !== "-"
                        ? user
                        : "",

                event: "HTTP Request",

                message:
                    `${request} | HTTP ${status} | ${size} bytes`

            });

        });


        return entries;

    }


    /* =====================================================
       SYSLOG PARSER
    ===================================================== */

    function parseSyslog(lines) {

        const entries = [];


        const pattern =
            /^([A-Z][a-z]{2}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\s+(\S+)\s+(.*)$/;


        lines.forEach(line => {

            const match =
                line.match(pattern);


            if (!match) {

                entries.push({
                    raw: line,
                    message: line
                });

                return;

            }


            const [
                ,
                timestamp,
                hostname,
                remainder
            ] = match;


            const level =
                extractLevel(remainder);


            const ip =
                extractIPAddress(remainder);


            const username =
                extractUsername(remainder);


            const event =
                detectEvent(remainder);


            entries.push({

                raw: line,

                timestamp,

                level,

                ip,

                username,

                event,

                message:
                    remainder

            });

        });


        return entries;

    }


    /* =====================================================
       GENERIC LOG PARSER
    ===================================================== */

    function parseGeneric(lines) {

        return lines.map(line => {

            const cleanLine = line.trim();


            const timestamp =
                extractTimestamp(cleanLine);


            const level =
                extractLevel(cleanLine);


            const ip =
                extractIPAddress(cleanLine);


            const username =
                extractUsername(cleanLine);


            const event =
                detectEvent(cleanLine);


            return {

                raw: line,

                timestamp,

                level,

                ip,

                username,

                event,

                message: cleanLine

            };

        });

    }


    /* =====================================================
       FIELD EXTRACTION
    ===================================================== */

    function extractTimestamp(text) {

        const patterns = [

            /\b\d{4}-\d{2}-\d{2}[T\s]\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:\d{2})?\b/,

            /\b\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2}\b/,

            /\b\d{2}\/\d{2}\/\d{4}\s+\d{2}:\d{2}:\d{2}\b/,

            /\b\d{2}-\d{2}-\d{4}\s+\d{2}:\d{2}:\d{2}\b/,

            /\b[A-Z][a-z]{2}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2}\b/,

            /\b\d{2}:\d{2}:\d{2}\b/
        ];


        for (const pattern of patterns) {

            const match =
                text.match(pattern);


            if (match) {
                return match[0];
            }

        }


        return "";

    }


    function extractLevel(text) {

        const bracketMatch =
            text.match(
                /\[\s*(DEBUG|INFO|NOTICE|WARNING|WARN|ERROR|CRITICAL|ALERT|EMERGENCY)\s*\]/i
            );


        if (bracketMatch) {
            return normalizeLevel(bracketMatch[1]);
        }


        const separatorMatch =
            text.match(
                /(?:^|\s)(DEBUG|INFO|NOTICE|WARNING|WARN|ERROR|CRITICAL|ALERT|EMERGENCY)(?:\s|:|]|-)/i
            );


        if (separatorMatch) {
            return normalizeLevel(separatorMatch[1]);
        }


        return inferLevelFromContent(text);

    }


    function inferLevelFromContent(text) {

        if (
            /\b(critical|fatal|panic|emergency|alert)\b/i
                .test(text)
        ) {

            return "CRITICAL";

        }


        if (
            /\b(error|exception|failed|failure|denied|blocked)\b/i
                .test(text)
        ) {

            return "ERROR";

        }


        if (
            /\b(warning|warn|suspicious)\b/i
                .test(text)
        ) {

            return "WARNING";

        }


        if (
            /\b(debug|trace)\b/i
                .test(text)
        ) {

            return "DEBUG";

        }


        return "INFO";

    }


    function normalizeLevel(level) {

        const normalized =
            String(level || "")
                .trim()
                .toUpperCase();


        if (normalized === "WARN") {
            return "WARNING";
        }


        if (
            [
                "CRITICAL",
                "ALERT",
                "EMERGENCY"
            ].includes(normalized)
        ) {

            return "CRITICAL";

        }


        if (LOG_LEVELS.includes(normalized)) {
            return normalized;
        }


        return "INFO";

    }


    function extractIPAddress(text) {

        const ipv4 =
            text.match(
                /\b(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(?:\.(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}\b/
            );


        if (ipv4) {
            return ipv4[0];
        }


        const ipv6 =
            text.match(
                /\b(?:[0-9a-fA-F]{1,4}:){2,7}[0-9a-fA-F]{1,4}\b/
            );


        if (ipv6) {
            return ipv6[0];
        }


        return "";

    }


    function extractUsername(text) {

        const patterns = [

            /(?:username|user|account|login|usr)\s*[=:]\s*["']?([a-zA-Z0-9._@-]+)/i,

            /\buser\s+["']?([a-zA-Z0-9._@-]+)["']?/i,

            /\bfor\s+user\s+["']?([a-zA-Z0-9._@-]+)["']?/i,

            /\buser=([a-zA-Z0-9._@-]+)/i,

            /\blogin=([a-zA-Z0-9._@-]+)/i

        ];


        for (const pattern of patterns) {

            const match =
                text.match(pattern);


            if (match) {
                return match[1];
            }

        }


        return "";

    }


    function detectEvent(text) {

        for (const event of EVENT_PATTERNS) {

            const matched =
                event.patterns.some(pattern =>
                    pattern.test(text)
                );


            if (matched) {
                return event.name;
            }

        }


        return "General Activity";

    }


    /* =====================================================
       NORMALIZATION
    ===================================================== */

    function normalizeEntry(entry, id) {

        const raw =
            String(entry.raw || entry.message || "");


        const timestamp =
            String(
                entry.timestamp ||
                extractTimestamp(raw) ||
                ""
            ).trim();


        const level =
            normalizeLevel(
                entry.level ||
                extractLevel(raw)
            );


        const ip =
            String(
                entry.ip ||
                extractIPAddress(raw) ||
                ""
            ).trim();


        const username =
            String(
                entry.username ||
                extractUsername(raw) ||
                ""
            ).trim();


        const event =
            String(
                entry.event ||
                detectEvent(raw) ||
                "General Activity"
            ).trim();


        const message =
            String(
                entry.message ||
                raw
            ).trim();


        return {

            id,

            timestamp,

            level,

            ip,

            username,

            event,

            message,

            raw

        };

    }


    /* =====================================================
       UTILITY FUNCTIONS
    ===================================================== */

    function firstValue(object, keys) {

        for (const key of keys) {

            if (
                Object.prototype.hasOwnProperty.call(
                    object,
                    key
                )
            ) {

                const value = object[key];


                if (
                    value !== undefined &&
                    value !== null &&
                    String(value).trim() !== ""
                ) {

                    return String(value).trim();

                }

            }

        }


        return "";

    }


    /* =====================================================
       EXPORT PUBLIC METHODS
    ===================================================== */

    return {

        parseFile,

        parseContent,

        detectFormat,

        extractTimestamp,

        extractLevel,

        extractIPAddress,

        extractUsername,

        detectEvent

    };

})();


/* =========================================================
   BACKWARD-COMPATIBLE GLOBAL ACCESS
========================================================= */

window.TraceXParser = TraceXParser;