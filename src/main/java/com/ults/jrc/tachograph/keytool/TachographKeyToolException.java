package com.ults.jrc.tachograph.keytool;

/**
 * Runtime exception thrown by Generation-2 Smart Tachograph Key Tool.
 *
 * @author Klaas Mateboer
 */
public class TachographKeyToolException extends RuntimeException {

    public TachographKeyToolException(String message) {
        super(message);
    }

    public TachographKeyToolException(String message, Throwable cause) {
        super(message, cause);
    }
}
