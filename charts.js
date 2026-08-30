/**
 * =========================================================
 * TRACEX - CHARTS
 * =========================================================
 *
 * Responsible for:
 * - Creating and updating all dashboard charts
 * - Timeline visualization
 * - IP distribution
 * - Log level distribution
 * - Event distribution
 * - Statistics page charts
 * - Chart cleanup/reinitialization
 *
 * Requires Chart.js to be loaded before this file.
 * =========================================================
 */

const TraceXCharts = (() => {

    "use strict";


    /* =====================================================
       CHART STORAGE
    ===================================================== */

    const charts = {};


    /* =====================================================
       DEFAULT OPTIONS
    ===================================================== */

    const FONT_FAMILY =
        'Inter, ui-sans-serif, system-ui, -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif';


    const GRID_COLOR =
        "rgba(145, 161, 178, 0.08)";


    const TEXT_COLOR =
        "#6f8193";


    const TOOLTIP_BACKGROUND =
        "#0d1721";


    const TOOLTIP_BORDER =
        "#243446";


    /* =====================================================
       CHART.JS CHECK
    ===================================================== */

    function isChartJSAvailable() {

        return typeof Chart !== "undefined";

    }


    /* =====================================================
       INITIALIZE
    ===================================================== */

    function initialize() {

        if (!isChartJSAvailable()) {

            console.warn(
                "TraceXCharts: Chart.js is not available."
            );

            return;

        }


        applyGlobalDefaults();

        resizeCanvases();

    }


    /* =====================================================
       GLOBAL CHART DEFAULTS
    ===================================================== */

    function applyGlobalDefaults() {

        Chart.defaults.font.family =
            FONT_FAMILY;

        Chart.defaults.font.size = 10;

        Chart.defaults.color =
            TEXT_COLOR;

        Chart.defaults.animation.duration =
            450;

        Chart.defaults.animation.easing =
            "easeOutQuart";

        Chart.defaults.plugins.legend.labels.usePointStyle =
            true;

        Chart.defaults.plugins.legend.labels.boxWidth =
            8;

        Chart.defaults.plugins.legend.labels.padding =
            12;

    }


    /* =====================================================
       TIMELINE CHART
    ===================================================== */

    function createTimelineChart(
        data = {}
    ) {

        const canvas =
            getCanvas(
                "logsTimelineChart"
            );


        if (!canvas) {
            return null;
        }


        destroyChart(
            "logsTimelineChart"
        );


        const normalized =
            normalizeTimelineData(data);


        const chart =
            new Chart(
                canvas.getContext("2d"),
                {

                    type: "line",

                    data: {

                        labels:
                            normalized.labels,

                        datasets: [

                            {

                                label: "Log Events",

                                data:
                                    normalized.values,

                                borderColor:
                                    "#35d0ff",

                                backgroundColor:
                                    "rgba(53, 208, 255, 0.08)",

                                borderWidth: 2,

                                pointRadius: 2,

                                pointHoverRadius: 5,

                                pointBackgroundColor:
                                    "#35d0ff",

                                pointBorderColor:
                                    "#071018",

                                tension: 0.35,

                                fill: true

                            }

                        ]

                    },

                    options: {

                        responsive: true,

                        maintainAspectRatio: false,

                        interaction: {

                            mode: "index",

                            intersect: false

                        },

                        plugins: {

                            legend: {
                                display: false
                            },

                            tooltip: {

                                backgroundColor:
                                    TOOLTIP_BACKGROUND,

                                borderColor:
                                    TOOLTIP_BORDER,

                                borderWidth: 1,

                                titleColor:
                                    "#edf3f8",

                                bodyColor:
                                    "#91a1b2",

                                padding: 10,

                                displayColors: false

                            }

                        },

                        scales: {

                            x: {

                                grid: {
                                    display: false
                                },

                                border: {
                                    display: false
                                },

                                ticks: {

                                    color:
                                        TEXT_COLOR,

                                    maxRotation: 0,

                                    autoSkip: true,

                                    maxTicksLimit: 8

                                }

                            },

                            y: {

                                beginAtZero: true,

                                grid: {
                                    color: GRID_COLOR
                                },

                                border: {
                                    display: false
                                },

                                ticks: {

                                    color:
                                        TEXT_COLOR,

                                    precision: 0

                                }

                            }

                        }

                    }

                }
            );


        charts.logsTimelineChart =
            chart;


        return chart;

    }


    /* =====================================================
       IP DOUGHNUT CHART
    ===================================================== */

    function createIPChart(
        data = []
    ) {

        const canvas =
            getCanvas(
                "ipChart"
            );


        if (!canvas) {
            return null;
        }


        destroyChart(
            "ipChart"
        );


        const normalized =
            normalizeRankingData(
                data,
                "ip"
            );


        const chart =
            new Chart(
                canvas.getContext("2d"),
                {

                    type: "doughnut",

                    data: {

                        labels:
                            normalized.labels,

                        datasets: [

                            {

                                data:
                                    normalized.values,

                                backgroundColor:
                                    buildChartColors(
                                        normalized.labels.length
                                    ),

                                borderColor:
                                    "#0d141e",

                                borderWidth: 2,

                                hoverOffset: 5

                            }

                        ]

                    },

                    options: {

                        responsive: true,

                        maintainAspectRatio: false,

                        cutout: "68%",

                        plugins: {

                            legend: {

                                position: "bottom",

                                labels: {

                                    color:
                                        "#8194a7",

                                    font: {
                                        size: 8
                                    },

                                    usePointStyle: true,

                                    pointStyle:
                                        "circle",

                                    padding: 10

                                }

                            },

                            tooltip: {

                                backgroundColor:
                                    TOOLTIP_BACKGROUND,

                                borderColor:
                                    TOOLTIP_BORDER,

                                borderWidth: 1,

                                padding: 9,

                                callbacks: {

                                    label(context) {

                                        const value =
                                            context.raw || 0;

                                        return `${context.label}: ${value}`;

                                    }

                                }

                            }

                        }

                    }

                }
            );


        charts.ipChart =
            chart;


        return chart;

    }


    /* =====================================================
       LOG LEVEL DOUGHNUT
    ===================================================== */

    function createLogLevelChart(
        data = {}
    ) {

        const canvas =
            getCanvas(
                "logLevelChart"
            );


        if (!canvas) {
            return null;
        }


        destroyChart(
            "logLevelChart"
        );


        const normalized =
            normalizeObjectData(
                data
            );


        const levelColors =
            normalized.labels.map(
                getLevelColor
            );


        const chart =
            new Chart(
                canvas.getContext("2d"),
                {

                    type: "doughnut",

                    data: {

                        labels:
                            normalized.labels,

                        datasets: [

                            {

                                data:
                                    normalized.values,

                                backgroundColor:
                                    levelColors,

                                borderColor:
                                    "#0d141e",

                                borderWidth: 2,

                                hoverOffset: 5

                            }

                        ]

                    },

                    options: {

                        responsive: true,

                        maintainAspectRatio: false,

                        cutout: "68%",

                        plugins: {

                            legend: {

                                position: "bottom",

                                labels: {

                                    color:
                                        "#8194a7",

                                    font: {
                                        size: 8
                                    },

                                    usePointStyle: true,

                                    pointStyle:
                                        "circle",

                                    padding: 10

                                }

                            },

                            tooltip: {

                                backgroundColor:
                                    TOOLTIP_BACKGROUND,

                                borderColor:
                                    TOOLTIP_BORDER,

                                borderWidth: 1,

                                padding: 9

                            }

                        }

                    }

                }
            );


        charts.logLevelChart =
            chart;


        return chart;

    }


    /* =====================================================
       STATISTICS TIMELINE
    ===================================================== */

    function createStatisticsTimelineChart(
        data = {}
    ) {

        const canvas =
            getCanvas(
                "statisticsTimelineChart"
            );


        if (!canvas) {
            return null;
        }


        destroyChart(
            "statisticsTimelineChart"
        );


        const normalized =
            normalizeTimelineData(data);


        const chart =
            new Chart(
                canvas.getContext("2d"),
                {

                    type: "bar",

                    data: {

                        labels:
                            normalized.labels,

                        datasets: [

                            {

                                label:
                                    "Events",

                                data:
                                    normalized.values,

                                backgroundColor:
                                    "rgba(53, 208, 255, 0.55)",

                                borderColor:
                                    "#35d0ff",

                                borderWidth: 1,

                                borderRadius: 4,

                                maxBarThickness: 25

                            }

                        ]

                    },

                    options: {

                        responsive: true,

                        maintainAspectRatio: false,

                        plugins: {

                            legend: {
                                display: false
                            },

                            tooltip: {

                                backgroundColor:
                                    TOOLTIP_BACKGROUND,

                                borderColor:
                                    TOOLTIP_BORDER,

                                borderWidth: 1,

                                padding: 10

                            }

                        },

                        scales: {

                            x: {

                                grid: {
                                    display: false
                                },

                                border: {
                                    display: false
                                },

                                ticks: {

                                    color:
                                        TEXT_COLOR,

                                    maxRotation: 0,

                                    autoSkip: true,

                                    maxTicksLimit: 10

                                }

                            },

                            y: {

                                beginAtZero: true,

                                grid: {
                                    color: GRID_COLOR
                                },

                                border: {
                                    display: false
                                },

                                ticks: {

                                    color:
                                        TEXT_COLOR,

                                    precision: 0

                                }

                            }

                        }

                    }

                }
            );


        charts.statisticsTimelineChart =
            chart;


        return chart;

    }


    /* =====================================================
       EVENT DISTRIBUTION
    ===================================================== */

    function createEventDistributionChart(
        data = {}
    ) {

        const canvas =
            getCanvas(
                "eventDistributionChart"
            );


        if (!canvas) {
            return null;
        }


        destroyChart(
            "eventDistributionChart"
        );


        const normalized =
            normalizeObjectData(
                data
            );


        const chart =
            new Chart(
                canvas.getContext("2d"),
                {

                    type: "polarArea",

                    data: {

                        labels:
                            normalized.labels,

                        datasets: [

                            {

                                data:
                                    normalized.values,

                                backgroundColor:
                                    buildChartColors(
                                        normalized.labels.length
                                    ),

                                borderColor:
                                    "#0d141e",

                                borderWidth: 2

                            }

                        ]

                    },

                    options: {

                        responsive: true,

                        maintainAspectRatio: false,

                        scales: {

                            r: {

                                beginAtZero: true,

                                grid: {
                                    color: GRID_COLOR
                                },

                                angleLines: {
                                    color: GRID_COLOR
                                },

                                ticks: {

                                    color:
                                        TEXT_COLOR,

                                    backdropColor:
                                        "transparent",

                                    precision: 0

                                }

                            }

                        },

                        plugins: {

                            legend: {

                                position: "bottom",

                                labels: {

                                    color:
                                        "#8194a7",

                                    font: {
                                        size: 8
                                    },

                                    usePointStyle: true,

                                    pointStyle:
                                        "circle",

                                    padding: 9

                                }

                            },

                            tooltip: {

                                backgroundColor:
                                    TOOLTIP_BACKGROUND,

                                borderColor:
                                    TOOLTIP_BORDER,

                                borderWidth: 1,

                                padding: 9

                            }

                        }

                    }

                }
            );


        charts.eventDistributionChart =
            chart;


        return chart;

    }


    /* =====================================================
       DASHBOARD UPDATE
    ===================================================== */

    function updateDashboard(
        analysis = {}
    ) {

        if (!analysis) {
            return;
        }


        createTimelineChart(
            analysis.timeline || {}
        );


        createIPChart(
            analysis.topIPs ||
            analysis.ips ||
            []
        );


        createLogLevelChart(
            analysis.levels || {}
        );

    }


    /* =====================================================
       STATISTICS UPDATE
    ===================================================== */

    function updateStatistics(
        analysis = {}
    ) {

        if (!analysis) {
            return;
        }


        createStatisticsTimelineChart(
            analysis.timeline || {}
        );


        createEventDistributionChart(
            analysis.events || {}
        );

    }


    /* =====================================================
       UPDATE ALL
    ===================================================== */

    function updateAll(
        analysis = {}
    ) {

        updateDashboard(
            analysis
        );

        updateStatistics(
            analysis
        );

    }


    /* =====================================================
       TIMELINE FILTERING
    ===================================================== */

    function filterTimeline(
        timeline = {},
        range = "all"
    ) {

        const normalized =
            normalizeTimelineData(
                timeline
            );


        if (
            range === "all" ||
            normalized.labels.length === 0
        ) {

            return normalized;

        }


        const days =
            getRangeDays(
                range
            );


        if (!days) {
            return normalized;
        }


        const cutoff =
            new Date();


        cutoff.setHours(
            0,
            0,
            0,
            0
        );


        cutoff.setDate(
            cutoff.getDate() - days + 1
        );


        const labels = [];

        const values = [];


        normalized.labels.forEach(
            (label, index) => {

                const date =
                    parseDateKey(
                        label
                    );


                if (
                    !date ||
                    date >= cutoff
                ) {

                    labels.push(
                        label
                    );

                    values.push(
                        normalized.values[index]
                    );

                }

            }
        );


        return {
            labels,
            values
        };

    }


    function updateTimelineRange(
        timeline,
        range
    ) {

        const filtered =
            filterTimeline(
                timeline,
                range
            );


        const chart =
            charts.logsTimelineChart;


        if (!chart) {

            createTimelineChart(
                filtered
            );

            return;

        }


        chart.data.labels =
            filtered.labels;


        chart.data.datasets[0].data =
            filtered.values;


        chart.update();

    }


    function getRangeDays(range) {

        switch (range) {

            case "24h":
                return 1;

            case "7d":
                return 7;

            case "30d":
                return 30;

            default:
                return null;

        }

    }


    /* =====================================================
       NORMALIZATION HELPERS
    ===================================================== */

    function normalizeTimelineData(
        data
    ) {

        if (
            Array.isArray(data)
        ) {

            const sorted =
                [...data].sort(
                    compareTimelineItems
                );


            return {

                labels:
                    sorted.map(
                        item =>
                            String(
                                item.date ||
                                item.label ||
                                ""
                            )
                    ),

                values:
                    sorted.map(
                        item =>
                            Number(
                                item.count ||
                                item.value ||
                                0
                            )
                    )

            };

        }


        if (
            data &&
            typeof data === "object"
        ) {

            return Object.entries(data)

                .sort(
                    ([dateA], [dateB]) =>
                        String(dateA)
                            .localeCompare(
                                String(dateB)
                            )
                )

                .map(
                    ([label, value]) => ({
                        label,
                        value:
                            Number(value) || 0
                    })
                )

                .reduce(
                    (result, item) => {

                        result.labels.push(
                            item.label
                        );

                        result.values.push(
                            item.value
                        );

                        return result;

                    },
                    {
                        labels: [],
                        values: []
                    }
                );

        }


        return {
            labels: [],
            values: []
        };

    }


    function compareTimelineItems(
        a,
        b
    ) {

        return String(
            a.date ||
            a.label ||
            ""
        ).localeCompare(
            String(
                b.date ||
                b.label ||
                ""
            )
        );

    }


    function normalizeObjectData(
        data
    ) {

        if (
            !data ||
            typeof data !== "object"
        ) {

            return {
                labels: [],
                values: []
            };

        }


        const entries =
            Object.entries(
                data
            )
                .filter(
                    ([, value]) =>
                        Number(value) >= 0
                )
                .sort(
                    ([, a], [, b]) =>
                        Number(b) - Number(a)
                );


        return {

            labels:
                entries.map(
                    ([label]) =>
                        label
                ),

            values:
                entries.map(
                    ([, value]) =>
                        Number(value) || 0
                )

        };

    }


    function normalizeRankingData(
        data,
        key
    ) {

        if (
            Array.isArray(data)
        ) {

            return {

                labels:
                    data
                        .slice(0, 8)
                        .map(
                            item =>
                                String(
                                    item[key] ||
                                    item.name ||
                                    item.label ||
                                    "Unknown"
                                )
                        ),

                values:
                    data
                        .slice(0, 8)
                        .map(
                            item =>
                                Number(
                                    item.count ||
                                    item.value ||
                                    0
                                )
                        )

            };

        }


        return normalizeObjectData(
            data
        );

    }


    /* =====================================================
       COLOR HELPERS
    ===================================================== */

    function buildChartColors(
        count
    ) {

        const palette = [

            "#35d0ff",

            "#33d69f",

            "#9a7cff",

            "#ffb84d",

            "#ff5d73",

            "#ff8e53",

            "#66a6ff",

            "#c084fc",

            "#4ade80",

            "#f472b6"

        ];


        const colors = [];


        for (
            let index = 0;
            index < count;
            index++
        ) {

            colors.push(
                palette[
                    index %
                    palette.length
                ]
            );

        }


        return colors;

    }


    function getLevelColor(
        level
    ) {

        const normalized =
            String(
                level || ""
            )
                .toUpperCase();


        switch (normalized) {

            case "DEBUG":
                return "#9a7cff";

            case "INFO":
                return "#35d0ff";

            case "NOTICE":
                return "#66a6ff";

            case "WARNING":
                return "#ffb84d";

            case "ERROR":
                return "#ff5d73";

            case "CRITICAL":
                return "#e63b57";

            default:
                return "#607487";

        }

    }


    /* =====================================================
       CANVAS HELPERS
    ===================================================== */

    function getCanvas(
        id
    ) {

        const canvas =
            document.getElementById(
                id
            );


        if (!canvas) {

            console.warn(
                `TraceXCharts: Canvas "${id}" was not found.`
            );

            return null;

        }


        return canvas;

    }


    function destroyChart(
        id
    ) {

        const chart =
            charts[id];


        if (!chart) {
            return;
        }


        try {
            chart.destroy();
        } catch (error) {

            console.warn(
                `TraceXCharts: Unable to destroy chart "${id}".`,
                error
            );

        }


        delete charts[id];

    }


    function destroyAll() {

        Object.keys(charts)
            .forEach(
                destroyChart
            );

    }


    function getChart(
        id
    ) {

        return charts[id] || null;

    }


    /* =====================================================
       DATE HELPERS
    ===================================================== */

    function parseDateKey(
        value
    ) {

        const direct =
            new Date(value);


        if (
            !Number.isNaN(
                direct.getTime()
            )
        ) {

            return direct;

        }


        const match =
            String(value)
                .match(
                    /^(\d{4})-(\d{2})-(\d{2})$/
                );


        if (!match) {
            return null;
        }


        return new Date(

            Number(match[1]),

            Number(match[2]) - 1,

            Number(match[3])

        );

    }


    /* =====================================================
       CANVAS RESIZE
    ===================================================== */

    function resizeCanvases() {

        window.requestAnimationFrame(
            () => {

                Object.values(charts)
                    .forEach(chart => {

                        try {
                            chart.resize();
                        } catch {
                            /* Ignore resize errors */
                        }

                    });

            }
        );

    }


    /* =====================================================
       EMPTY CHART STATE
    ===================================================== */

    function showEmptyChart(
        id,
        message = "No data available"
    ) {

        const canvas =
            getCanvas(id);


        if (!canvas) {
            return;
        }


        destroyChart(id);


        const context =
            canvas.getContext("2d");


        const width =
            canvas.width ||
            canvas.parentElement?.clientWidth ||
            300;


        const height =
            canvas.height ||
            canvas.parentElement?.clientHeight ||
            180;


        context.clearRect(
            0,
            0,
            width,
            height
        );


        context.save();

        context.fillStyle =
            "#506173";

        context.font =
            `10px ${FONT_FAMILY}`;

        context.textAlign =
            "center";

        context.textBaseline =
            "middle";


        context.fillText(
            message,
            width / 2,
            height / 2
        );


        context.restore();

    }


    /* =====================================================
       EXPORT PUBLIC API
    ===================================================== */

    return {

        initialize,

        createTimelineChart,

        createIPChart,

        createLogLevelChart,

        createStatisticsTimelineChart,

        createEventDistributionChart,

        updateDashboard,

        updateStatistics,

        updateAll,

        filterTimeline,

        updateTimelineRange,

        showEmptyChart,

        destroyChart,

        destroyAll,

        getChart

    };

})();


/* =========================================================
   GLOBAL ACCESS
========================================================= */

window.TraceXCharts =
    TraceXCharts;