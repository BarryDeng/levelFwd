package edu.nuaa.levelFwd;

public enum Level {
    WHITELIST(10000, "11:11:11:11:11:11"),
    RELIABLE(10001, "22:22:22:22:22:22"),
    NORMAL(10002, "f2:ed:50:4d:ee:6f"),
    THREAT(10003, "44:44:44:44:44:44"),
    BLACKLIST(10004, "55:55:55:55:55:55");

    private int code;
    private String MAC;
    private Level(int code, String mac) {
        this.code = code;
        this.MAC = mac;
    }

    public int getCode() {
        return code;
    }

    public String getMAC() {
        return MAC;
    }

    public void setCode(int code) {
        this.code = code;
    }

    public void setMAC(String MAC) {
        this.MAC = MAC;
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