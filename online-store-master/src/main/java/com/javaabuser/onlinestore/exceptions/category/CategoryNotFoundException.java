package com.javaabuser.onlinestore.exceptions.category;

public class CategoryNotFoundException extends RuntimeException{
    public CategoryNotFoundException() {
        super("Category not found.");
    }

    public CategoryNotFoundException(String message) {
        super(message);
    }

    public CategoryNotFoundException(String message, Throwable cause) {
        super(message, cause);
    }

    public CategoryNotFoundException(Throwable cause) {
        super(cause);
    }

    protected CategoryNotFoundException(String message, Throwable cause, boolean enableSuppression, boolean writableStackTrace) {
        super(message, cause, enableSuppression, writableStackTrace);
    }
}
