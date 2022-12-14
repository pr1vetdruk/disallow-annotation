package ru.somsin.disallowannotation.model;

import java.lang.reflect.Method;
import java.util.Objects;

/**
 * Method data
 */
public class MethodData {
    /**
     * Method
     */
    private Method method;

    /**
     * Forbidden annotation indication
     */
    private boolean hasForbiddenAnnotation;

    public MethodData(Method method, boolean hasForbiddenAnnotation) {
        this.method = method;
        this.hasForbiddenAnnotation = hasForbiddenAnnotation;
    }

    public Method getMethod() {
        return method;
    }

    public void setMethod(Method method) {
        this.method = method;
    }

    public boolean isHasForbiddenAnnotation() {
        return hasForbiddenAnnotation;
    }

    public void setHasForbiddenAnnotation(boolean hasForbiddenAnnotation) {
        this.hasForbiddenAnnotation = hasForbiddenAnnotation;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        MethodData that = (MethodData) o;
        return Objects.equals(method, that.method);
    }

    @Override
    public int hashCode() {
        return Objects.hash(method);
    }
}
