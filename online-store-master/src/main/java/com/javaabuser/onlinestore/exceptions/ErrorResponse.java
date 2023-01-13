package com.javaabuser.onlinestore.exceptions;

import java.util.Date;

public class ErrorResponse {
    private String message;
    private Date timestamp;

    public ErrorResponse(String message, Date timestamp) {
        this.message = message;
        this.timestamp = timestamp;
    }

    public ErrorResponse() {
    }

    public String getMessage() {
        return message;
    }

    public void setMessage(String message) {
        this.message = message;
    }

    public Date getTimestamp() {
        return timestamp;
    }

    public void setTimestamp(Date timestamp) {
        this.timestamp = timestamp;
    }
}
