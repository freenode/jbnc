class Connections {
    constructor() {
        this.connections = {};
    }

    userChannelCount(hash) {
        if (this.connections.hasOwnProperty(hash) && this.connections[hash].channels)
            return Object.keys(this.connections[hash].channels).length;
        else
            return null;
    }

    userChannels(hash) {
        let channels = [];
        for (let key in this.connections[hash].channels) {
            if (this.connections[hash].channels.hasOwnProperty(key)) {
                channels.push(this.connections[hash].channels[key].name);
            }
        }
        return channels;
    }
}

module.exports = Connections;