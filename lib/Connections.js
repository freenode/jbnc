class Connections {
    constructor() {
        this.connections = {};
    }

    userChannelCount(hash) {
        const channels = this.connections?.[hash]?.channels;
        return channels ? Object.keys(channels).length : null;
    }

    userChannels(hash) {
        if (!this.connections?.[hash]?.channels) {
            return [];
        }

        let channels = [];
        for (let key in this.connections[hash].channels) {
            if (Object.prototype.hasOwnProperty.call(this.connections[hash].channels, key)) {
                channels.push(this.connections[hash].channels[key].name);
            }
        }
        return channels;
    }

    userKill(hash) {
        let disconnected = false;
        if (this.connections[hash]) {
            this.connections[hash].end();
            disconnected=true;
        }
        return disconnected;
    }
}

module.exports = Connections;