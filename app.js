/**
 * =========================================================
 * TRACEX - APPLICATION CONTROLLER
 * =========================================================
 *
 * Connects:
 * - parser.js
 * - analyzer.js
 * - detector.js
 * - charts.js
 * - index.html
 *
 * Handles:
 * - Navigation
 * - File uploads
 * - Log parsing
 * - Analysis
 * - Threat detection
 * - Dashboard rendering
 * - Search and filters
 * - Scan history
 * - Export
 * - Reports
 * - Modals
 * - Settings
 * - Notifications
 * =========================================================
 */

(() => {

    "use strict";


    /* =====================================================
       APPLICATION STATE
    ===================================================== */

    const state = {

        logs: [],

        filteredLogs: [],

        analysis: null,

        detections: null,

        currentFile: null,

        currentPage: "dashboard",

        searchResults: [],

        scanHistory: [],

        settings: {

            bruteForceDetection: true,

            suspiciousDetection: true,

            animations: true

        }

    };


    /* =====================================================
       DOM CACHE
    ===================================================== */

    const elements = {};


    /* =====================================================
       INITIALIZATION
    ===================================================== */

    document.addEventListener(
        "DOMContentLoaded",
        init
    );


    function init() {

        cacheElements();

        loadSettings();

        loadScanHistory();

        setupNavigation();

        setupFileInputs();

        setupDashboardActions();

        setupLogViewer();

        setupAdvancedSearch();

        setupSettings();

        setupModals();

        setupExportButtons();

        setupResponsiveNavigation();

        initializeCharts();

        renderInitialState();

    }


    /* =====================================================
       DOM CACHE
    ===================================================== */

    function cacheElements() {

        const ids = [

            "sidebar",
            "sidebarToggle",
            "mobileMenu",

            "logFileInput",
            "dashboardFileInput",

            "currentFileName",
            "currentFileMeta",

            "exportBtn",
            "reportBtn",
            "helpBtn",

            "clearLogsBtn",

            "totalLogs",
            "uniqueIPs",
            "totalUsers",
            "failedLogins",
            "suspiciousEvents",
            "bruteForceAlerts",

            "summaryTotalLogs",
            "summaryUniqueIPs",
            "summaryUsers",
            "summaryFailedLogins",
            "summarySuspicious",
            "summaryBruteForce",
            "lastScan",

            "suspiciousBadge",
            "bruteForceBadge",

            "dashboardSearch",
            "quickFilterBtn",
            "timeRange",

            "recentLogsTable",
            "allLogsTable",

            "logViewerSearch",
            "levelFilter",
            "eventFilter",
            "resetFiltersBtn",

            "advancedSearch",
            "advancedLevel",
            "advancedIP",
            "advancedUser",
            "advancedSearchBtn",
            "searchResultCount",
            "searchResults",

            "ipAnalysisTable",
            "userAnalysisTable",

            "failedLoginPageCount",
            "failedLoginIPs",
            "failedLoginUsers",
            "failedLoginsTable",

            "suspiciousEventsList",
            "bruteForceResults",

            "historyTable",

            "generateReportBtn",
            "exportLogsBtn",

            "bruteForceSetting",
            "suspiciousSetting",
            "animationsSetting",

            "logDetailModal",
            "closeLogModal",
            "logDetailContent",

            "helpModal",
            "closeHelpModal",

            "toastContainer"

        ];


        ids.forEach(id => {

            elements[id] =
                document.getElementById(id);

        });

    }


    /* =====================================================
       NAVIGATION
    ===================================================== */

    function setupNavigation() {

        const navItems =
            document.querySelectorAll(
                ".nav-item[data-page]"
            );


        navItems.forEach(item => {

            item.addEventListener(
                "click",
                () => {

                    const page =
                        item.dataset.page;


                    navigateTo(
                        page
                    );

                }
            );

        });


        const pageButtons =
            document.querySelectorAll(
                "[data-page]:not(.nav-item)"
            );


        pageButtons.forEach(button => {

            button.addEventListener(
                "click",
                () => {

                    const page =
                        button.dataset.page;


                    if (page) {

                        navigateTo(
                            page
                        );

                    }

                }
            );

        });

    }


    function navigateTo(page) {

        if (!page) {
            return;
        }


        const pages =
            document.querySelectorAll(
                ".page"
            );


        const navItems =
            document.querySelectorAll(
                ".nav-item[data-page]"
            );


        pages.forEach(currentPage => {

            currentPage.classList.remove(
                "active"
            );

        });


        navItems.forEach(item => {

            item.classList.remove(
                "active"
            );

        });


        const targetPage =
            document.getElementById(
                `${page}Page`
            );


        if (!targetPage) {

            showToast(
                "Page is not available.",
                "warning"
            );

            return;

        }


        targetPage.classList.add(
            "active"
        );


        const activeNav =
            document.querySelector(
                `.nav-item[data-page="${page}"]`
            );


        if (activeNav) {

            activeNav.classList.add(
                "active"
            );

        }


        state.currentPage =
            page;


        if (
            page === "statistics" &&
            state.analysis
        ) {

            TraceXCharts.updateStatistics(
                state.analysis
            );

        }


        if (page === "logs") {

            renderAllLogs();

        }


        if (page === "ip-analysis") {

            renderIPAnalysis();

        }


        if (page === "user-analysis") {

            renderUserAnalysis();

        }


        if (page === "failed-logins") {

            renderFailedLogins();

        }


        if (page === "suspicious") {

            renderSuspiciousEvents();

        }


        if (page === "brute-force") {

            renderBruteForceResults();

        }


        if (page === "history") {

            renderHistory();

        }


        closeSidebarOnMobile();

        window.scrollTo({
            top: 0,
            behavior: "smooth"
        });

    }


    /* =====================================================
       FILE INPUTS
    ===================================================== */

    function setupFileInputs() {

        if (elements.logFileInput) {

            elements.logFileInput.addEventListener(
                "change",
                handleFileSelection
            );

        }


        if (elements.dashboardFileInput) {

            elements.dashboardFileInput.addEventListener(
                "change",
                handleFileSelection
            );

        }

    }


    async function handleFileSelection(event) {

        const file =
            event.target.files?.[0];


        if (!file) {
            return;
        }


        await analyzeFile(
            file
        );


        event.target.value = "";

    }


    async function analyzeFile(file) {

        if (!file) {
            return;
        }


        const supportedTypes = [

            ".log",
            ".txt",
            ".csv",
            ".json"

        ];


        const extension =
            getFileExtension(
                file.name
            );


        if (
            !supportedTypes.includes(
                extension
            )
        ) {

            showToast(
                "Unsupported file type. Use LOG, TXT, CSV, or JSON.",
                "error"
            );

            return;

        }


        try {

            showToast(
                "Reading log file...",
                "info"
            );


            const parsed =
                await TraceXParser.parseFile(
                    file
                );


            if (
                !parsed ||
                !Array.isArray(
                    parsed.entries
                )
            ) {

                throw new Error(
                    "The log file could not be parsed."
                );

            }


            state.currentFile =
                file;


            state.logs =
                parsed.entries;


            state.filteredLogs =
                [...state.logs];


            /* ---------------------------------------------
               Analyze
            --------------------------------------------- */

            state.analysis =
                TraceXAnalyzer.analyze(
                    state.logs
                );


            /* ---------------------------------------------
               Detection
            --------------------------------------------- */

            state.detections =
                runDetection();


            /* ---------------------------------------------
               Update interface
            --------------------------------------------- */

            updateFileInformation(
                file,
                parsed
            );


            updateDashboard();


            updateAllTables();


            updateCharts();


            updateHistory();


            updateLastScan();


            showToast(
                `${state.logs.length.toLocaleString()} log entries analyzed.`,
                "success"
            );

        } catch (error) {

            console.error(
                "TraceX analysis error:",
                error
            );


            showToast(
                error?.message ||
                "Unable to analyze the selected file.",
                "error"
            );

        }

    }


    function runDetection() {

        if (
            !state.settings.suspiciousDetection
        ) {

            return {

                totalLogs:
                    state.logs.length,

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

        }


        const detection =
            TraceXDetector.analyze(
                state.logs
            );


        if (
            !state.settings.bruteForceDetection
        ) {

            detection.bruteForceAttacks =
                [];

            detection.suspiciousEvents =
                detection.suspiciousEvents
                    .filter(
                        item =>
                            item.type !==
                            "brute-force"
                    );

        }


        detection.threatCount =
            detection.suspiciousEvents.length;


        return detection;

    }


    /* =====================================================
       FILE INFORMATION
    ===================================================== */

    function updateFileInformation(
        file,
        parsed
    ) {

        if (elements.currentFileName) {

            elements.currentFileName.textContent =
                file.name;

        }


        if (elements.currentFileMeta) {

            const size =
                formatBytes(
                    file.size
                );


            const format =
                parsed.format
                    ? parsed.format.toUpperCase()
                    : "UNKNOWN";


            elements.currentFileMeta.textContent =
                `${format} • ${size} • ${parsed.entries.length.toLocaleString()} parsed entries`;

        }

    }


    /* =====================================================
       DASHBOARD
    ===================================================== */

    function updateDashboard() {

        if (!state.analysis) {
            return;
        }


        const analysis =
            state.analysis;


        const detections =
            state.detections || {};


        setText(
            elements.totalLogs,
            analysis.totalLogs
        );


        setText(
            elements.uniqueIPs,
            analysis.uniqueIPs
        );


        setText(
            elements.totalUsers,
            analysis.totalUsers
        );


        setText(
            elements.failedLogins,
            analysis.failedLogins
        );


        setText(
            elements.suspiciousEvents,
            detections.threatCount || 0
        );


        setText(
            elements.bruteForceAlerts,
            detections.bruteForceAttacks?.length || 0
        );


        setText(
            elements.summaryTotalLogs,
            analysis.totalLogs
        );


        setText(
            elements.summaryUniqueIPs,
            analysis.uniqueIPs
        );


        setText(
            elements.summaryUsers,
            analysis.totalUsers
        );


        setText(
            elements.summaryFailedLogins,
            analysis.failedLogins
        );


        setText(
            elements.summarySuspicious,
            detections.threatCount || 0
        );


        setText(
            elements.summaryBruteForce,
            detections.bruteForceAttacks?.length || 0
        );


        setText(
            elements.suspiciousBadge,
            detections.threatCount || 0
        );


        setText(
            elements.bruteForceBadge,
            detections.bruteForceAttacks?.length || 0
        );


        renderRecentLogs();

        renderTopUsers();

        renderRecentAlerts();

    }


    /* =====================================================
       RECENT LOGS
    ===================================================== */

    function renderRecentLogs() {

        if (!elements.recentLogsTable) {
            return;
        }


        const logs =
            state.logs
                .slice(-10)
                .reverse();


        if (logs.length === 0) {

            elements.recentLogsTable.innerHTML =
                createEmptyTableRow(
                    6,
                    "No logs loaded",
                    "Upload a log file to begin analysis."
                );

            return;

        }


        elements.recentLogsTable.innerHTML =
            logs
                .map(
                    (log, index) =>
                        createLogRow(
                            log,
                            index,
                            false
                        )
                )
                .join("");


        attachLogRowEvents(
            elements.recentLogsTable
        );

    }


    /* =====================================================
       ALL LOGS
    ===================================================== */

    function renderAllLogs() {

        if (!elements.allLogsTable) {
            return;
        }


        let logs =
            [...state.logs];


        const search =
            elements.logViewerSearch?.value
                ?.trim()
                .toLowerCase();


        const level =
            elements.levelFilter?.value ||
            "all";


        const event =
            elements.eventFilter?.value ||
            "all";


        if (
            search ||
            level !== "all" ||
            event !== "all"
        ) {

            logs =
                TraceXAnalyzer.filterLogs(
                    logs,
                    {

                        query:
                            search || "",

                        level,

                        event

                    }
                );

        }


        state.filteredLogs =
            logs;


        if (logs.length === 0) {

            elements.allLogsTable.innerHTML =
                createEmptyTableRow(
                    7,
                    "No matching logs",
                    "Try changing your search or filters."
                );

            return;

        }


        elements.allLogsTable.innerHTML =
            logs
                .map(
                    (log, index) =>
                        createLogRow(
                            log,
                            index,
                            true
                        )
                )
                .join("");


        attachLogRowEvents(
            elements.allLogsTable
        );

    }


    function createLogRow(
        log,
        index,
        showNumber
    ) {

        const levelClass =
            getLevelClass(
                log.level
            );


        const timestamp =
            escapeHTML(
                log.timestamp ||
                "-"
            );


        const ip =
            escapeHTML(
                log.ip ||
                "-"
            );


        const username =
            escapeHTML(
                log.username ||
                "-"
            );


        const event =
            escapeHTML(
                log.event ||
                "General Activity"
            );


        const message =
            escapeHTML(
                log.message ||
                "-"
            );


        const numberCell =
            showNumber
                ? `<td>${index + 1}</td>`
                : "";


        return `

            <tr
                class="log-row"
                data-log-id="${escapeAttribute(
                    log.id
                )}"
            >

                ${numberCell}

                <td title="${timestamp}">
                    ${timestamp}
                </td>

                <td>
                    <span class="level-badge ${levelClass}">
                        ${escapeHTML(
                            normalizeDisplayLevel(
                                log.level
                            )
                        )}
                    </span>
                </td>

                <td>
                    <span class="ip-value">
                        ${ip}
                    </span>
                </td>

                <td>
                    ${username}
                </td>

                <td>
                    ${event}
                </td>

                <td title="${message}">
                    ${truncateText(
                        message,
                        90
                    )}
                </td>

            </tr>
        `;

    }


    function attachLogRowEvents(
        container
    ) {

        const rows =
            container.querySelectorAll(
                ".log-row"
            );


        rows.forEach(row => {

            row.addEventListener(
                "click",
                () => {

                    const id =
                        row.dataset.logId;


                    const log =
                        state.logs.find(
                            item =>
                                String(
                                    item.id
                                ) === String(id)
                        );


                    if (log) {

                        openLogDetail(
                            log
                        );

                    }

                }
            );

        });

    }


    /* =====================================================
       TOP USERS
    ===================================================== */

    function renderTopUsers() {

        if (!elements.topUsersList) {
            return;
        }


        const users =
            state.analysis?.topUsers ||
            [];


        if (users.length === 0) {

            elements.topUsersList.innerHTML =
                `<div class="empty-mini">
                    No user data
                </div>`;

            return;

        }


        elements.topUsersList.innerHTML =
            users
                .slice(0, 6)
                .map(user => {

                    const username =
                        escapeHTML(
                            user.username
                        );


                    const initial =
                        escapeHTML(
                            String(
                                user.username
                            )
                                .charAt(0)
                                .toUpperCase()
                        );


                    return `

                        <div
                            class="user-row"
                            data-username="${escapeAttribute(
                                user.username
                            )}"
                        >

                            <div class="user-avatar">
                                ${initial}
                            </div>

                            <div class="user-info">

                                <strong>
                                    ${username}
                                </strong>

                                <span>
                                    ${user.failedLogins || 0}
                                    failed login${user.failedLogins === 1 ? "" : "s"}
                                </span>

                            </div>

                            <div class="user-count">
                                ${user.count}
                            </div>

                        </div>

                    `;

                })
                .join("");

    }


    /* =====================================================
       ALERTS
    ===================================================== */

    function renderRecentAlerts() {

        if (!elements.recentAlertsList) {
            return;
        }


        const alerts =
            state.detections?.suspiciousEvents ||
            [];


        if (alerts.length === 0) {

            elements.recentAlertsList.innerHTML =
                `<div class="empty-mini">
                    No alerts detected
                </div>`;

            return;

        }


        const recent =
            [...alerts]
                .sort(
                    compareDetectionTime
                )
                .slice(0, 5);


        elements.recentAlertsList.innerHTML =
            recent
                .map(
                    createAlertMarkup
                )
                .join("");

    }


    function createAlertMarkup(
        alert
    ) {

        const severity =
            normalizeSeverity(
                alert.severity
            );


        const title =
            escapeHTML(
                alert.name ||
                "Security Alert"
            );


        const description =
            escapeHTML(
                alert.description ||
                alert.message ||
                "Suspicious activity detected."
            );


        const time =
            formatAlertTime(
                alert.timestamp
            );


        return `

            <div
                class="alert-item"
                data-alert-id="${escapeAttribute(
                    alert.id || ""
                )}"
            >

                <div class="alert-icon">
                    ⚠
                </div>

                <div class="alert-content">

                    <strong>
                        ${title}
                    </strong>

                    <span>
                        ${description}
                    </span>

                </div>

                <div class="alert-time">
                    ${time}
                </div>

            </div>

        `;

    }


    /* =====================================================
       LOG VIEWER
    ===================================================== */

    function setupLogViewer() {

        if (elements.logViewerSearch) {

            elements.logViewerSearch.addEventListener(
                "input",
                debounce(
                    renderAllLogs,
                    120
                )
            );

        }


        if (elements.levelFilter) {

            elements.levelFilter.addEventListener(
                "change",
                renderAllLogs
            );

        }


        if (elements.eventFilter) {

            elements.eventFilter.addEventListener(
                "change",
                renderAllLogs
            );

        }


        if (elements.resetFiltersBtn) {

            elements.resetFiltersBtn.addEventListener(
                "click",
                resetViewerFilters
            );

        }

    }


    function resetViewerFilters() {

        if (elements.logViewerSearch) {
            elements.logViewerSearch.value =
                "";
        }


        if (elements.levelFilter) {
            elements.levelFilter.value =
                "all";
        }


        if (elements.eventFilter) {
            elements.eventFilter.value =
                "all";
        }


        renderAllLogs();

    }


    function populateEventFilter() {

        if (!elements.eventFilter) {
            return;
        }


        const current =
            elements.eventFilter.value;


        const events =
            Object.keys(
                state.analysis?.events || {}
            )
                .sort();


        elements.eventFilter.innerHTML = `

            <option value="all">
                All Events
            </option>

            ${events
                .map(
                    event => `
                        <option value="${escapeAttribute(
                            event
                        )}">
                            ${escapeHTML(
                                event
                            )}
                        </option>
                    `
                )
                .join("")}

        `;


        if (
            events.includes(
                current
            )
        ) {

            elements.eventFilter.value =
                current;

        }

    }


    /* =====================================================
       DASHBOARD SEARCH
    ===================================================== */

    function setupDashboardActions() {

        if (elements.dashboardSearch) {

            elements.dashboardSearch.addEventListener(
                "input",
                debounce(
                    () => {

                        const query =
                            elements.dashboardSearch
                                .value
                                .trim();


                        const logs =
                            query
                                ? TraceXAnalyzer.filterLogs(
                                    state.logs,
                                    {
                                        query
                                    }
                                )
                                : state.logs.slice()
                                    .reverse();


                        renderDashboardSearchResults(
                            logs
                        );

                    },
                    120
                )
            );

        }


        if (elements.quickFilterBtn) {

            elements.quickFilterBtn.addEventListener(
                "click",
                () => {

                    navigateTo(
                        "search"
                    );

                }
            );

        }


        if (elements.clearLogsBtn) {

            elements.clearLogsBtn.addEventListener(
                "click",
                clearAnalysis
            );

        }


        if (elements.timeRange) {

            elements.timeRange.addEventListener(
                "change",
                () => {

                    if (
                        state.analysis
                    ) {

                        TraceXCharts.updateTimelineRange(
                            state.analysis.timeline,
                            elements.timeRange.value
                        );

                    }

                }
            );

        }

    }


    function renderDashboardSearchResults(
        logs
    ) {

        if (!elements.recentLogsTable) {
            return;
        }


        if (logs.length === 0) {

            elements.recentLogsTable.innerHTML =
                createEmptyTableRow(
                    6,
                    "No matching logs",
                    "Try another search term."
                );

            return;

        }


        elements.recentLogsTable.innerHTML =
            logs
                .slice(0, 10)
                .map(
                    (log, index) =>
                        createLogRow(
                            log,
                            index,
                            false
                        )
                )
                .join("");


        attachLogRowEvents(
            elements.recentLogsTable
        );

    }


    /* =====================================================
       ADVANCED SEARCH
    ===================================================== */

    function setupAdvancedSearch() {

        if (elements.advancedSearchBtn) {

            elements.advancedSearchBtn.addEventListener(
                "click",
                runAdvancedSearch
            );

        }


        [

            elements.advancedSearch,
            elements.advancedIP,
            elements.advancedUser

        ].forEach(input => {

            if (!input) {
                return;
            }


            input.addEventListener(
                "keydown",
                event => {

                    if (
                        event.key === "Enter"
                    ) {

                        runAdvancedSearch();

                    }

                }
            );

        });

    }


    function runAdvancedSearch() {

        const options = {

            query:
                elements.advancedSearch
                    ?.value
                    ?.trim() || "",

            level:
                elements.advancedLevel
                    ?.value ||
                "all",

            ip:
                elements.advancedIP
                    ?.value
                    ?.trim() || "",

            username:
                elements.advancedUser
                    ?.value
                    ?.trim() || "",

            event: "all"

        };


        const results =
            TraceXAnalyzer.filterLogs(
                state.logs,
                options
            );


        state.searchResults =
            results;


        renderSearchResults(
            results
        );

    }


    function renderSearchResults(
        results
    ) {

        if (
            elements.searchResultCount
        ) {

            elements.searchResultCount.textContent =
                `${results.length.toLocaleString()} ${
                    results.length === 1
                        ? "result"
                        : "results"
                }`;

        }


        if (!elements.searchResults) {
            return;
        }


        if (results.length === 0) {

            elements.searchResults.innerHTML =
                `

                <div class="empty-state">

                    <div class="empty-icon">
                        ⌕
                    </div>

                    <h4>
                        No matching logs
                    </h4>

                    <p>
                        Try changing your search criteria.
                    </p>

                </div>

                `;

            return;

        }


        elements.searchResults.innerHTML = `

            <div class="table-wrapper">

                <table class="logs-table">

                    <thead>

                        <tr>

                            <th>Time</th>
                            <th>Level</th>
                            <th>IP Address</th>
                            <th>User</th>
                            <th>Event</th>
                            <th>Message</th>

                        </tr>

                    </thead>

                    <tbody>

                        ${results
                            .slice(0, 500)
                            .map(
                                (log, index) =>
                                    createLogRow(
                                        log,
                                        index,
                                        false
                                    )
                            )
                            .join("")}

                    </tbody>

                </table>

            </div>

        `;


        const tableBody =
            elements.searchResults
                .querySelector(
                    "tbody"
                );


        if (tableBody) {

            attachLogRowEvents(
                tableBody
            );

        }

    }


    /* =====================================================
       IP ANALYSIS
    ===================================================== */

    function renderIPAnalysis() {

        if (!elements.ipAnalysisTable) {
            return;
        }


        const ipData =
            Object.values(
                state.analysis?.ips || {}
            )
                .sort(
                    (a, b) =>
                        b.count - a.count
                );


        if (ipData.length === 0) {

            elements.ipAnalysisTable.innerHTML =
                `

                <tr>

                    <td colspan="5">

                        <div class="empty-state">

                            <div class="empty-icon">
                                ◎
                            </div>

                            <h4>
                                No IP data
                            </h4>

                            <p>
                                Analyze a log file first.
                            </p>

                        </div>

                    </td>

                </tr>

                `;

            return;

        }


        elements.ipAnalysisTable.innerHTML =
            ipData
                .map(
                    data => {

                        const risk =
                            TraceXAnalyzer.calculateIPRisk(
                                data
                            );


                        return `

                            <tr>

                                <td>
                                    <strong>
                                        ${escapeHTML(
                                            data.ip
                                        )}
                                    </strong>
                                </td>

                                <td>
                                    ${data.count}
                                </td>

                                <td>
                                    ${data.failedLogins}
                                </td>

                                <td>
                                    ${Object.keys(
                                        data.users || {}
                                    ).length}
                                </td>

                                <td>

                                    <span class="risk-badge ${risk}">
                                        ${risk.toUpperCase()}
                                    </span>

                                </td>

                            </tr>

                        `;

                    }
                )
                .join("");

    }


    /* =====================================================
       USER ANALYSIS
    ===================================================== */

    function renderUserAnalysis() {

        if (!elements.userAnalysisTable) {
            return;
        }


        const userData =
            Object.values(
                state.analysis?.users || {}
            )
                .sort(
                    (a, b) =>
                        b.count - a.count
                );


        if (userData.length === 0) {

            elements.userAnalysisTable.innerHTML =
                `

                <tr>

                    <td colspan="5">

                        <div class="empty-state">

                            <div class="empty-icon">
                                ♙
                            </div>

                            <h4>
                                No user data
                            </h4>

                            <p>
                                Analyze a log file first.
                            </p>

                        </div>

                    </td>

                </tr>

                `;

            return;

        }


        elements.userAnalysisTable.innerHTML =
            userData
                .map(
                    data => {

                        const risk =
                            TraceXAnalyzer.calculateUserRisk(
                                data
                            );


                        return `

                            <tr>

                                <td>
                                    <strong>
                                        ${escapeHTML(
                                            data.username
                                        )}
                                    </strong>
                                </td>

                                <td>
                                    ${data.count}
                                </td>

                                <td>
                                    ${data.successfulLogins}
                                </td>

                                <td>
                                    ${data.failedLogins}
                                </td>

                                <td>

                                    <span class="risk-badge ${risk}">
                                        ${risk.toUpperCase()}
                                    </span>

                                </td>

                            </tr>

                        `;

                    }
                )
                .join("");

    }


    /* =====================================================
       FAILED LOGINS
    ===================================================== */

    function renderFailedLogins() {

        const failed =
            state.analysis?.failedLoginEntries ||
            [];


        const uniqueIPs =
            new Set(
                failed
                    .map(
                        log =>
                            log.ip
                    )
                    .filter(Boolean)
            );


        const uniqueUsers =
            new Set(
                failed
                    .map(
                        log =>
                            log.username
                    )
                    .filter(Boolean)
            );


        setText(
            elements.failedLoginPageCount,
            failed.length
        );


        setText(
            elements.failedLoginIPs,
            uniqueIPs.size
        );


        setText(
            elements.failedLoginUsers,
            uniqueUsers.size
        );


        if (!elements.failedLoginsTable) {
            return;
        }


        if (failed.length === 0) {

            elements.failedLoginsTable.innerHTML =
                createEmptyTableRow(
                    5,
                    "No failed logins",
                    "No authentication failures were detected."
                );

            return;

        }


        elements.failedLoginsTable.innerHTML =
            failed
                .slice()
                .reverse()
                .slice(0, 500)
                .map(
                    log => `

                        <tr
                            class="log-row"
                            data-log-id="${escapeAttribute(
                                log.id
                            )}"
                        >

                            <td>
                                ${escapeHTML(
                                    log.timestamp || "-"
                                )}
                            </td>

                            <td>
                                ${escapeHTML(
                                    log.ip || "-"
                                )}
                            </td>

                            <td>
                                ${escapeHTML(
                                    log.username || "-"
                                )}
                            </td>

                            <td>
                                ${escapeHTML(
                                    log.event || "Failed Login"
                                )}
                            </td>

                            <td title="${escapeAttribute(
                                log.message || ""
                            )}">
                                ${truncateText(
                                    escapeHTML(
                                        log.message || "-"
                                    ),
                                    110
                                )}
                            </td>

                        </tr>

                    `
                )
                .join("");


        attachLogRowEvents(
            elements.failedLoginsTable
        );

    }


    /* =====================================================
       SUSPICIOUS EVENTS
    ===================================================== */

    function renderSuspiciousEvents() {

        if (!elements.suspiciousEventsList) {
            return;
        }


        const alerts =
            state.detections?.suspiciousEvents ||
            [];


        if (alerts.length === 0) {

            elements.suspiciousEventsList.innerHTML =
                `

                <div class="empty-state large-empty">

                    <div class="empty-icon">
                        ⚠
                    </div>

                    <h4>
                        No suspicious events
                    </h4>

                    <p>
                        Security detections will appear here after analysis.
                    </p>

                </div>

                `;

            return;

        }


        const sorted =
            [...alerts]
                .sort(
                    compareDetectionSeverity
                );


        elements.suspiciousEventsList.innerHTML =
            sorted
                .map(
                    alert =>
                        createSecurityAlertCard(
                            alert
                        )
                )
                .join("");

    }


    function createSecurityAlertCard(
        alert
    ) {

        const severity =
            normalizeSeverity(
                alert.severity
            );


        return `

            <div class="security-alert">

                <div class="security-alert-icon">
                    ⚠
                </div>

                <div class="security-alert-content">

                    <h4>
                        ${escapeHTML(
                            alert.name ||
                            "Security Alert"
                        )}
                    </h4>

                    <p>
                        ${escapeHTML(
                            alert.description ||
                            alert.message ||
                            "Suspicious activity detected."
                        )}
                    </p>

                    <p>
                        ${
                            alert.ip
                                ? `IP: ${escapeHTML(
                                    alert.ip
                                )}`
                                : ""
                        }

                        ${
                            alert.username
                                ? ` • User: ${escapeHTML(
                                    alert.username
                                )}`
                                : ""
                        }
                    </p>

                </div>

                <div class="security-alert-meta">

                    <span>
                        ${escapeHTML(
                            alert.timestamp ||
                            "-"
                        )}
                    </span>

                    <strong>
                        ${severity.toUpperCase()}
                    </strong>

                </div>

            </div>

        `;

    }


    /* =====================================================
       BRUTE FORCE
    ===================================================== */

    function renderBruteForceResults() {

        if (!elements.bruteForceResults) {
            return;
        }


        const attacks =
            state.detections?.bruteForceAttacks ||
            [];


        if (attacks.length === 0) {

            elements.bruteForceResults.innerHTML =
                `

                <div class="empty-state large-empty">

                    <div class="empty-icon">
                        ◎
                    </div>

                    <h4>
                        No brute-force attacks detected
                    </h4>

                    <p>
                        Detection results will appear here after log analysis.
                    </p>

                </div>

                `;

            return;

        }


        elements.bruteForceResults.innerHTML =
            attacks
                .map(
                    attack => {

                        const severity =
                            normalizeSeverity(
                                attack.severity
                            );


                        return `

                            <div class="brute-force-card">

                                <div class="brute-force-header">

                                    <h4>
                                        ${escapeHTML(
                                            attack.name
                                        )}
                                    </h4>

                                    <span>
                                        ${severity.toUpperCase()}
                                    </span>

                                </div>

                                <div>

                                    <p style="
                                        margin-top: 8px;
                                        color: #6f8193;
                                        font-size: 9px;
                                    ">
                                        ${escapeHTML(
                                            attack.description
                                        )}
                                    </p>

                                </div>

                                <div class="brute-force-details">

                                    <div>

                                        <span>
                                            Source IP
                                        </span>

                                        <strong>
                                            ${escapeHTML(
                                                attack.ip ||
                                                "Unknown"
                                            )}
                                        </strong>

                                    </div>

                                    <div>

                                        <span>
                                            Attempts
                                        </span>

                                        <strong>
                                            ${attack.count || 0}
                                        </strong>

                                    </div>

                                    <div>

                                        <span>
                                            Username
                                        </span>

                                        <strong>
                                            ${escapeHTML(
                                                attack.username ||
                                                attack.logs?.[0]
                                                    ?.username ||
                                                "Multiple / Unknown"
                                            )}
                                        </strong>

                                    </div>

                                    <div>

                                        <span>
                                            Severity
                                        </span>

                                        <strong>
                                            ${severity.toUpperCase()}
                                        </strong>

                                    </div>

                                </div>

                            </div>

                        `;

                    }
                )
                .join("");

    }


    /* =====================================================
       CHARTS
    ===================================================== */

    function initializeCharts() {

        if (
            window.TraceXCharts &&
            typeof TraceXCharts.initialize ===
            "function"
        ) {

            TraceXCharts.initialize();

        }

    }


    function updateCharts() {

        if (!state.analysis) {
            return;
        }


        if (
            window.TraceXCharts &&
            typeof TraceXCharts.updateAll ===
            "function"
        ) {

            TraceXCharts.updateAll(
                state.analysis
            );

        }

    }


    /* =====================================================
       TABLE UPDATE
    ===================================================== */

    function updateAllTables() {

        populateEventFilter();

        renderAllLogs();

        renderIPAnalysis();

        renderUserAnalysis();

        renderFailedLogins();

        renderSuspiciousEvents();

        renderBruteForceResults();

        renderHistory();

    }


    /* =====================================================
       HISTORY
    ===================================================== */

    function loadScanHistory() {

        try {

            const stored =
                localStorage.getItem(
                    "tracex_scan_history"
                );


            if (!stored) {
                state.scanHistory = [];
                return;
            }


            const parsed =
                JSON.parse(
                    stored
                );


            state.scanHistory =
                Array.isArray(parsed)
                    ? parsed
                    : [];

        } catch {

            state.scanHistory =
                [];

        }

    }


    function updateHistory() {

        if (!state.currentFile) {
            return;
        }


        const analysis =
            state.analysis;


        const detections =
            state.detections;


        if (!analysis) {
            return;
        }


        const scan = {

            id:
                Date.now(),

            date:
                new Date().toISOString(),

            file:
                state.currentFile.name,

            totalLogs:
                analysis.totalLogs,

            threats:
                detections?.threatCount || 0,

            status:
                detections?.status || "clean"

        };


        state.scanHistory =
            [
                scan,
                ...state.scanHistory
            ]
                .slice(0, 50);


        try {

            localStorage.setItem(
                "tracex_scan_history",
                JSON.stringify(
                    state.scanHistory
                )
            );

        } catch (error) {

            console.warn(
                "Unable to save scan history:",
                error
            );

        }


        renderHistory();

    }


    function renderHistory() {

        if (!elements.historyTable) {
            return;
        }


        if (
            state.scanHistory.length === 0
        ) {

            elements.historyTable.innerHTML =
                `

                <tr>

                    <td colspan="5">

                        <div class="empty-state">

                            <div class="empty-icon">
                                ◷
                            </div>

                            <h4>
                                No scan history
                            </h4>

                            <p>
                                Your analysis sessions will appear here.
                            </p>

                        </div>

                    </td>

                </tr>

                `;

            return;

        }


        elements.historyTable.innerHTML =
            state.scanHistory
                .map(
                    scan => {

                        const status =
                            escapeHTML(
                                scan.status ||
                                "clean"
                            );


                        return `

                            <tr>

                                <td>
                                    ${formatDateTime(
                                        scan.date
                                    )}
                                </td>

                                <td>
                                    ${escapeHTML(
                                        scan.file ||
                                        "Unknown"
                                    )}
                                </td>

                                <td>
                                    ${Number(
                                        scan.totalLogs || 0
                                    ).toLocaleString()}
                                </td>

                                <td>
                                    ${Number(
                                        scan.threats || 0
                                    )}
                                </td>

                                <td>

                                    <span class="risk-badge ${getStatusClass(
                                        scan.status
                                    )}">
                                        ${status.toUpperCase()}
                                    </span>

                                </td>

                            </tr>

                        `;

                    }
                )
                .join("");

    }


    /* =====================================================
       LAST SCAN
    ===================================================== */

    function updateLastScan() {

        if (!elements.lastScan) {
            return;
        }


        elements.lastScan.textContent =
            new Date().toLocaleString();

    }


    /* =====================================================
       CLEAR ANALYSIS
    ===================================================== */

    function clearAnalysis() {

        if (
            state.logs.length === 0
        ) {

            showToast(
                "There is no analysis to clear.",
                "info"
            );

            return;

        }


        state.logs = [];

        state.filteredLogs = [];

        state.analysis = null;

        state.detections = null;

        state.currentFile = null;

        state.searchResults = [];


        if (elements.currentFileName) {

            elements.currentFileName.textContent =
                "No log file loaded";

        }


        if (elements.currentFileMeta) {

            elements.currentFileMeta.textContent =
                "Upload a log file to begin analysis";

        }


        resetCounters();

        renderInitialState();


        if (
            window.TraceXCharts
        ) {

            TraceXCharts.destroyAll();

        }


        showToast(
            "Current log analysis cleared.",
            "success"
        );

    }


    function resetCounters() {

        [

            elements.totalLogs,
            elements.uniqueIPs,
            elements.totalUsers,
            elements.failedLogins,
            elements.suspiciousEvents,
            elements.bruteForceAlerts,
            elements.summaryTotalLogs,
            elements.summaryUniqueIPs,
            elements.summaryUsers,
            elements.summaryFailedLogins,
            elements.summarySuspicious,
            elements.summaryBruteForce,
            elements.suspiciousBadge,
            elements.bruteForceBadge,
            elements.failedLoginPageCount,
            elements.failedLoginIPs,
            elements.failedLoginUsers

        ].forEach(
            element => {

                if (element) {
                    element.textContent =
                        "0";
                }

            }
        );


        if (elements.lastScan) {
            elements.lastScan.textContent =
                "No scan";
        }

    }


    /* =====================================================
       INITIAL STATE
    ===================================================== */

    function renderInitialState() {

        resetCounters();

        renderRecentLogs();

        renderTopUsers();

        renderRecentAlerts();

        renderAllLogs();

        renderIPAnalysis();

        renderUserAnalysis();

        renderFailedLogins();

        renderSuspiciousEvents();

        renderBruteForceResults();

        renderHistory();

    }


    /* =====================================================
       LOG DETAIL MODAL
    ===================================================== */

    function openLogDetail(log) {

        if (
            !elements.logDetailModal ||
            !elements.logDetailContent
        ) {

            return;

        }


        elements.logDetailContent.innerHTML = `

            <div class="detail-grid">

                <div class="detail-item">

                    <span>
                        Timestamp
                    </span>

                    <strong>
                        ${escapeHTML(
                            log.timestamp || "-"
                        )}
                    </strong>

                </div>

                <div class="detail-item">

                    <span>
                        Log Level
                    </span>

                    <strong>
                        ${escapeHTML(
                            normalizeDisplayLevel(
                                log.level
                            )
                        )}
                    </strong>

                </div>

                <div class="detail-item">

                    <span>
                        IP Address
                    </span>

                    <strong>
                        ${escapeHTML(
                            log.ip || "-"
                        )}
                    </strong>

                </div>

                <div class="detail-item">

                    <span>
                        Username
                    </span>

                    <strong>
                        ${escapeHTML(
                            log.username || "-"
                        )}
                    </strong>

                </div>

                <div class="detail-item">

                    <span>
                        Event
                    </span>

                    <strong>
                        ${escapeHTML(
                            log.event ||
                            "General Activity"
                        )}
                    </strong>

                </div>

                <div class="detail-item">

                    <span>
                        Entry ID
                    </span>

                    <strong>
                        ${escapeHTML(
                            String(
                                log.id ??
                                "-"
                            )
                        )}
                    </strong>

                </div>

                <div class="detail-item full">

                    <span>
                        Message
                    </span>

                    <strong>
                        ${escapeHTML(
                            log.message ||
                            "-"
                        )}
                    </strong>

                </div>

                <div class="detail-item full">

                    <span>
                        Raw Log
                    </span>

                    <strong>
                        ${escapeHTML(
                            log.raw ||
                            "-"
                        )}
                    </strong>

                </div>

            </div>

        `;


        elements.logDetailModal.classList.add(
            "active"
        );

    }


    function closeLogDetail() {

        elements.logDetailModal?.classList.remove(
            "active"
        );

    }


    /* =====================================================
       MODALS
    ===================================================== */

    function setupModals() {

        if (elements.closeLogModal) {

            elements.closeLogModal.addEventListener(
                "click",
                closeLogDetail
            );

        }


        if (elements.closeHelpModal) {

            elements.closeHelpModal.addEventListener(
                "click",
                closeHelpModal
            );

        }


        if (elements.helpBtn) {

            elements.helpBtn.addEventListener(
                "click",
                openHelpModal
            );

        }


        [

            elements.logDetailModal,
            elements.helpModal

        ].forEach(overlay => {

            if (!overlay) {
                return;
            }


            overlay.addEventListener(
                "click",
                event => {

                    if (
                        event.target ===
                        overlay
                    ) {

                        overlay.classList.remove(
                            "active"
                        );

                    }

                }
            );

        });


        document.addEventListener(
            "keydown",
            event => {

                if (
                    event.key !==
                    "Escape"
                ) {

                    return;

                }


                closeLogDetail();

                closeHelpModal();

            }
        );

    }


    function openHelpModal() {

        elements.helpModal?.classList.add(
            "active"
        );

    }


    function closeHelpModal() {

        elements.helpModal?.classList.remove(
            "active"
        );

    }


    /* =====================================================
       EXPORT
    ===================================================== */

    function setupExportButtons() {

        elements.exportBtn?.addEventListener(
            "click",
            exportFilteredLogs
        );


        elements.exportLogsBtn?.addEventListener(
            "click",
            exportFilteredLogs
        );


        elements.reportBtn?.addEventListener(
            "click",
            generateReport
        );


        elements.generateReportBtn?.addEventListener(
            "click",
            generateReport
        );

    }


    function exportFilteredLogs() {

        const logs =
            state.filteredLogs.length
                ? state.filteredLogs
                : state.logs;


        if (logs.length === 0) {

            showToast(
                "There are no logs to export.",
                "warning"
            );

            return;

        }


        const headers = [

            "Timestamp",
            "Level",
            "IP Address",
            "Username",
            "Event",
            "Message"

        ];


        const rows =
            logs.map(
                log => [

                    log.timestamp || "",

                    log.level || "",

                    log.ip || "",

                    log.username || "",

                    log.event || "",

                    log.message || ""

                ]
            );


        const csv =
            [
                headers,
                ...rows
            ]
                .map(
                    row =>
                        row
                            .map(
                                value =>
                                    csvEscape(
                                        value
                                    )
                            )
                            .join(",")
                )
                .join("\n");


        downloadFile(
            csv,
            `tracex-log-export-${timestampForFileName()}.csv`,
            "text/csv;charset=utf-8"
        );


        showToast(
            "Log data exported successfully.",
            "success"
        );

    }


    /* =====================================================
       REPORT GENERATION
    ===================================================== */

    function generateReport() {

        if (
            !state.analysis
        ) {

            showToast(
                "Analyze a log file before generating a report.",
                "warning"
            );

            return;

        }


        const analysis =
            state.analysis;


        const detections =
            state.detections || {};


        const report = {

            application:
                "TraceX",

            title:
                "TraceX Security Log Analysis Report",

            generatedAt:
                new Date().toISOString(),

            file:
                state.currentFile?.name ||
                "Unknown",

            format:
                getFileExtension(
                    state.currentFile?.name ||
                    ""
                ).replace(
                    ".",
                    ""
                ).toUpperCase(),

            summary: {

                totalLogs:
                    analysis.totalLogs,

                uniqueIPs:
                    analysis.uniqueIPs,

                totalUsers:
                    analysis.totalUsers,

                failedLogins:
                    analysis.failedLogins,

                successfulLogins:
                    analysis.successfulLogins,

                suspiciousEvents:
                    detections.threatCount ||
                    0,

                bruteForceAlerts:
                    detections.bruteForceAttacks
                        ?.length ||
                    0,

                status:
                    detections.status ||
                    "clean"

            },

            logLevels:
                analysis.levels,

            events:
                analysis.events,

            topIPs:
                analysis.topIPs,

            topUsers:
                analysis.topUsers,

            threats:
                detections.suspiciousEvents ||
                []

        };


        const text =
            buildReadableReport(
                report
            );


        downloadFile(
            text,
            `tracex-security-report-${timestampForFileName()}.txt`,
            "text/plain;charset=utf-8"
        );


        showToast(
            "Security report generated.",
            "success"
        );

    }


    function buildReadableReport(
        report
    ) {

        const lines = [];


        lines.push(
            "============================================================"
        );

        lines.push(
            "TRACEX - SECURITY LOG ANALYSIS REPORT"
        );

        lines.push(
            "============================================================"
        );

        lines.push("");


        lines.push(
            `Generated: ${formatDateTime(
                report.generatedAt
            )}`
        );


        lines.push(
            `File: ${report.file}`
        );


        lines.push(
            `Format: ${report.format || "UNKNOWN"}`
        );


        lines.push("");


        lines.push(
            "SUMMARY"
        );


        lines.push(
            "------------------------------------------------------------"
        );


        Object.entries(
            report.summary
        ).forEach(
            ([key, value]) => {

                lines.push(
                    `${formatReportLabel(
                        key
                    )}: ${value}`
                );

            }
        );


        lines.push("");


        lines.push(
            "LOG LEVELS"
        );


        lines.push(
            "------------------------------------------------------------"
        );


        Object.entries(
            report.logLevels || {}
        ).forEach(
            ([key, value]) => {

                lines.push(
                    `${key}: ${value}`
                );

            }
        );


        lines.push("");


        lines.push(
            "TOP IP ADDRESSES"
        );


        lines.push(
            "------------------------------------------------------------"
        );


        report.topIPs
            ?.slice(0, 10)
            .forEach(
                item => {

                    lines.push(
                        `${item.ip} - ${item.count} events - ${item.failedLogins} failed logins`
                    );

                }
            );


        lines.push("");


        lines.push(
            "TOP USERS"
        );


        lines.push(
            "------------------------------------------------------------"
        );


        report.topUsers
            ?.slice(0, 10)
            .forEach(
                item => {

                    lines.push(
                        `${item.username} - ${item.count} events - ${item.failedLogins} failed logins`
                    );

                }
            );


        lines.push("");


        lines.push(
            "SECURITY DETECTIONS"
        );


        lines.push(
            "------------------------------------------------------------"
        );


        if (
            report.threats.length === 0
        ) {

            lines.push(
                "No suspicious activity detected."
            );

        } else {

            report.threats
                .forEach(
                    (alert, index) => {

                        lines.push(
                            `${index + 1}. ${alert.name || "Security Alert"}`
                        );

                        lines.push(
                            `   Severity: ${String(
                                alert.severity ||
                                "medium"
                            ).toUpperCase()}`
                        );


                        if (alert.ip) {

                            lines.push(
                                `   IP: ${alert.ip}`
                            );

                        }


                        if (alert.username) {

                            lines.push(
                                `   User: ${alert.username}`
                            );

                        }


                        lines.push(
                            `   Description: ${
                                alert.description ||
                                alert.message ||
                                ""
                            }`
                        );


                        lines.push("");

                    }
                );

        }


        lines.push(
            "============================================================"
        );


        lines.push(
            "Generated by TraceX"
        );


        return lines.join("\n");

    }


    /* =====================================================
       SETTINGS
    ===================================================== */

    function setupSettings() {

        if (elements.bruteForceSetting) {

            elements.bruteForceSetting.addEventListener(
                "change",
                () => {

                    state.settings.bruteForceDetection =
                        elements.bruteForceSetting.checked;


                    saveSettings();


                    if (state.logs.length > 0) {

                        state.detections =
                            runDetection();


                        updateDashboard();

                        updateAllTables();

                    }

                }
            );

        }


        if (elements.suspiciousSetting) {

            elements.suspiciousSetting.addEventListener(
                "change",
                () => {

                    state.settings.suspiciousDetection =
                        elements.suspiciousSetting.checked;


                    saveSettings();


                    if (state.logs.length > 0) {

                        state.detections =
                            runDetection();


                        updateDashboard();

                        updateAllTables();

                    }

                }
            );

        }


        if (elements.animationsSetting) {

            elements.animationsSetting.addEventListener(
                "change",
                () => {

                    state.settings.animations =
                        elements.animationsSetting.checked;


                    applyAnimationSetting();

                    saveSettings();

                }
            );

        }

    }


    function loadSettings() {

        try {

            const stored =
                localStorage.getItem(
                    "tracex_settings"
                );


            if (stored) {

                const parsed =
                    JSON.parse(
                        stored
                    );


                state.settings = {

                    ...state.settings,

                    ...parsed

                };

            }

        } catch (error) {

            console.warn(
                "Unable to load settings:",
                error
            );

        }


        applySettingsToUI();

        applyAnimationSetting();

    }


    function saveSettings() {

        try {

            localStorage.setItem(
                "tracex_settings",
                JSON.stringify(
                    state.settings
                )
            );

        } catch (error) {

            console.warn(
                "Unable to save settings:",
                error
            );

        }

    }


    function applySettingsToUI() {

        if (elements.bruteForceSetting) {

            elements.bruteForceSetting.checked =
                state.settings.bruteForceDetection;

        }


        if (elements.suspiciousSetting) {

            elements.suspiciousSetting.checked =
                state.settings.suspiciousDetection;

        }


        if (elements.animationsSetting) {

            elements.animationsSetting.checked =
                state.settings.animations;

        }

    }


    function applyAnimationSetting() {

        document.body.classList.toggle(
            "animations-disabled",
            !state.settings.animations
        );

    }


    /* =====================================================
       RESPONSIVE NAVIGATION
    ===================================================== */

    function setupResponsiveNavigation() {

        elements.sidebarToggle?.addEventListener(
            "click",
            toggleSidebar
        );


        elements.mobileMenu?.addEventListener(
            "click",
            toggleSidebar
        );


        document.addEventListener(
            "click",
            event => {

                if (
                    window.innerWidth > 760
                ) {
                    return;
                }


                if (
                    !elements.sidebar?.classList.contains(
                        "mobile-open"
                    )
                ) {
                    return;
                }


                const clickedSidebar =
                    elements.sidebar.contains(
                        event.target
                    );


                const clickedMenu =
                    elements.mobileMenu?.contains(
                        event.target
                    );


                if (
                    !clickedSidebar &&
                    !clickedMenu
                ) {

                    closeSidebarOnMobile();

                }

            }
        );

    }


    function toggleSidebar() {

        elements.sidebar?.classList.toggle(
            "mobile-open"
        );

    }


    function closeSidebarOnMobile() {

        if (
            window.innerWidth <= 760
        ) {

            elements.sidebar?.classList.remove(
                "mobile-open"
            );

        }

    }


    /* =====================================================
       UTILITY - TEXT
    ===================================================== */

    function setText(
        element,
        value
    ) {

        if (!element) {
            return;
        }


        element.textContent =
            Number.isFinite(
                Number(value)
            )
                ? Number(value).toLocaleString()
                : String(
                    value ??
                    ""
                );

    }


    function escapeHTML(value) {

        return String(
            value ??
            ""
        )
            .replace(
                /&/g,
                "&amp;"
            )
            .replace(
                /</g,
                "&lt;"
            )
            .replace(
                />/g,
                "&gt;"
            )
            .replace(
                /"/g,
                "&quot;"
            )
            .replace(
                /'/g,
                "&#039;"
            );

    }


    function escapeAttribute(value) {

        return escapeHTML(
            value
        );

    }


    function truncateText(
        text,
        maxLength
    ) {

        const value =
            String(
                text ||
                ""
            );


        if (
            value.length <=
            maxLength
        ) {

            return value;

        }


        return (
            value.slice(
                0,
                maxLength
            ) +
            "..."
        );

    }


    /* =====================================================
       UTILITY - LEVELS
    ===================================================== */

    function normalizeDisplayLevel(
        level
    ) {

        const value =
            String(
                level ||
                "INFO"
            )
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


        return value;

    }


    function getLevelClass(
        level
    ) {

        switch (
            normalizeDisplayLevel(
                level
            )
        ) {

            case "DEBUG":
                return "debug";

            case "WARNING":
            case "NOTICE":
                return "warning";

            case "ERROR":
            case "CRITICAL":
                return "error";

            default:
                return "info";

        }

    }


    /* =====================================================
       UTILITY - SEVERITY
    ===================================================== */

    function normalizeSeverity(
        severity
    ) {

        const value =
            String(
                severity ||
                "medium"
            )
                .toLowerCase();


        return [

            "low",
            "medium",
            "high",
            "critical"

        ].includes(value)

            ? value

            : "medium";

    }


    function getStatusClass(
        status
    ) {

        const normalized =
            normalizeSeverity(
                status
            );


        if (
            status ===
            "clean"
        ) {

            return "low";

        }


        return normalized;

    }


    /* =====================================================
       UTILITY - DETECTIONS
    ===================================================== */

    function compareDetectionSeverity(
        a,
        b
    ) {

        const ranks = {

            critical: 4,

            high: 3,

            medium: 2,

            low: 1

        };


        const severityA =
            normalizeSeverity(
                a?.severity
            );


        const severityB =
            normalizeSeverity(
                b?.severity
            );


        return (
            (ranks[severityB] || 0) -
            (ranks[severityA] || 0)
        );

    }


    function compareDetectionTime(
        a,
        b
    ) {

        const dateA =
            new Date(
                a?.detectedAt ||
                a?.timestamp ||
                0
            );


        const dateB =
            new Date(
                b?.detectedAt ||
                b?.timestamp ||
                0
            );


        return (
            dateB.getTime() -
            dateA.getTime()
        );

    }


    function formatAlertTime(
        timestamp
    ) {

        if (!timestamp) {
            return "-";
        }


        const date =
            new Date(
                timestamp
            );


        if (
            Number.isNaN(
                date.getTime()
            )
        ) {

            return String(
                timestamp
            );

        }


        return date.toLocaleTimeString(
            [],
            {
                hour: "2-digit",
                minute: "2-digit"
            }
        );

    }


    /* =====================================================
       UTILITY - DATE / TIME
    ===================================================== */

    function formatDateTime(
        value
    ) {

        if (!value) {
            return "-";
        }


        const date =
            new Date(
                value
            );


        if (
            Number.isNaN(
                date.getTime()
            )
        ) {

            return String(
                value
            );

        }


        return date.toLocaleString();

    }


    function timestampForFileName() {

        const now =
            new Date();


        const year =
            now.getFullYear();


        const month =
            String(
                now.getMonth() + 1
            ).padStart(
                2,
                "0"
            );


        const day =
            String(
                now.getDate()
            ).padStart(
                2,
                "0"
            );


        const hours =
            String(
                now.getHours()
            ).padStart(
                2,
                "0"
            );


        const minutes =
            String(
                now.getMinutes()
            ).padStart(
                2,
                "0"
            );


        const seconds =
            String(
                now.getSeconds()
            ).padStart(
                2,
                "0"
            );


        return (
            `${year}${month}${day}` +
            `-${hours}${minutes}${seconds}`
        );

    }


    /* =====================================================
       UTILITY - FILES
    ===================================================== */

    function getFileExtension(
        filename
    ) {

        const name =
            String(
                filename ||
                ""
            )
                .toLowerCase();


        const index =
            name.lastIndexOf(
                "."
            );


        return index === -1
            ? ""
            : name.slice(
                index
            );

    }


    function formatBytes(
        bytes
    ) {

        if (
            !Number.isFinite(
                Number(bytes)
            ) ||
            Number(bytes) <= 0
        ) {

            return "0 B";

        }


        const value =
            Number(bytes);


        const units = [

            "B",
            "KB",
            "MB",
            "GB"

        ];


        const exponent =
            Math.min(
                Math.floor(
                    Math.log(
                        value
                    ) /
                    Math.log(1024)
                ),
                units.length - 1
            );


        const size =
            value /
            Math.pow(
                1024,
                exponent
            );


        return `${size.toFixed(
            exponent === 0 ? 0 : 1
        )} ${units[exponent]}`;

    }


    function csvEscape(
        value
    ) {

        const string =
            String(
                value ??
                ""
            );


        return `"${string
            .replace(
                /"/g,
                '""'
            )}"`;

    }


    function downloadFile(
        content,
        filename,
        type
    ) {

        const blob =
            new Blob(
                [content],
                {
                    type
                }
            );


        const url =
            URL.createObjectURL(
                blob
            );


        const anchor =
            document.createElement(
                "a"
            );


        anchor.href =
            url;


        anchor.download =
            filename;


        document.body.appendChild(
            anchor
        );


        anchor.click();


        anchor.remove();


        URL.revokeObjectURL(
            url
        );

    }


    /* =====================================================
       UTILITY - EMPTY TABLE
    ===================================================== */

    function createEmptyTableRow(
        colspan,
        title,
        message
    ) {

        return `

            <tr class="empty-row">

                <td colspan="${colspan}">

                    <div class="empty-state">

                        <div class="empty-icon">
                            ▤
                        </div>

                        <h4>
                            ${escapeHTML(
                                title
                            )}
                        </h4>

                        <p>
                            ${escapeHTML(
                                message
                            )}
                        </p>

                    </div>

                </td>

            </tr>

        `;

    }


    /* =====================================================
       TOAST NOTIFICATIONS
    ===================================================== */

    function showToast(
        message,
        type = "info"
    ) {

        if (!elements.toastContainer) {
            return;
        }


        const toast =
            document.createElement(
                "div"
            );


        toast.className =
            `toast ${normalizeToastType(
                type
            )}`;


        toast.innerHTML = `

            <span>
                ${getToastIcon(
                    type
                )}
            </span>

            <span>
                ${escapeHTML(
                    message
                )}
            </span>

        `;


        elements.toastContainer.appendChild(
            toast
        );


        window.setTimeout(
            () => {

                toast.remove();

            },
            4200
        );

    }


    function normalizeToastType(
        type
    ) {

        return [

            "success",
            "error",
            "warning",
            "info"

        ].includes(type)

            ? type

            : "info";

    }


    function getToastIcon(
        type
    ) {

        switch (type) {

            case "success":
                return "✓";

            case "error":
                return "✕";

            case "warning":
                return "⚠";

            default:
                return "ℹ";

        }

    }


    /* =====================================================
       UTILITY - DEBOUNCE
    ===================================================== */

    function debounce(
        callback,
        delay
    ) {

        let timer;


        return (...args) => {

            clearTimeout(
                timer
            );


            timer =
                setTimeout(
                    () => {

                        callback(
                            ...args
                        );

                    },
                    delay
                );

        };

    }


    /* =====================================================
       PUBLIC DEBUG ACCESS
    ===================================================== */

    window.TraceXApp = {

        state,

        analyzeFile,

        navigateTo,

        clearAnalysis,

        exportFilteredLogs,

        generateReport,

        showToast

    };

})();