global.Reports = {};
const doreport = {
    addReport: function(id, report) {
        const timestamp = Date.now(); // Current time in milliseconds
        if (!id || id === 'sys') {
            id = timestamp; // Use timestamp as ID if none provided
        }
        const reportEntry = {
            id: id,
            time: new Date(timestamp).toLocaleString(), // Readable time
            timestamp: Math.floor(timestamp / 1000), // Unix timestamp in seconds
            report: report
        };

        // If the ID already exists, create an array or append to existing array
        if (!global.Reports[id]) {
            global.Reports[id] = [];
        }
        global.Reports[id].push(reportEntry);
    },

    clearReports: function(N) {
        const currentTime = Math.floor(Date.now() / 1000); 
        const thresholdTime = currentTime - (N * 3600);

        // Iterate through all IDs
        Object.keys(global.Reports).forEach(id => {
            // Filter out reports older than threshold for each ID
            global.Reports[id] = global.Reports[id].filter(
                reportEntry => reportEntry.timestamp >= thresholdTime
            );

            // Remove the ID key if no reports remain
            if (global.Reports[id].length === 0) {
                delete global.Reports[id];
            }
        });
    },

    getReports: function() {
        // Flatten all reports across IDs and sort by timestamp
        const allReports = Object.values(global.Reports)
            .flat()
            .sort((a, b) => b.timestamp - a.timestamp)
            .map((report, index) => ({
                id: index + 1, // Regenerate sequential IDs
                time: report.time,
                report: report.report
            }));

        return { reports: allReports };
    }
};

module.exports = doreport;