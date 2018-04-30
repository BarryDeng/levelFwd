package edu.nuaa.levelFwd;

public enum Level {
    WHITELIST(10000,(short)1),
    RELIABLE(10001, (short)2),
    NORMAL(10002, (short)3),
    THREAT(10003, (short)4),
    BLACKLIST(10004, (short)5);

    private int code;
    private short port;
    private Level(int code, short port) {
        this.code = code;
        this.port = port;
    }

    public int getCode() {
        return code;
    }

    public short getPort() {
        return port;
    }

    public void setCode(int code) {
        this.code = code;
    }

    public void setMAC(short port) {
        this.port = port;
    }

    public static Level getByValue(int value) {
        for (Level level : values()) {
            if (level.getCode() == value) {
                return level;
            }
        }

        return null;
    }

}