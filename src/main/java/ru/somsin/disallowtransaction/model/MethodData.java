package ru.somsin.disallowtransaction.model;

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
     * Transaction indication
     */
    private boolean hasTransactional;

    public MethodData(Method method, boolean hasTransactional) {
        this.method = method;
        this.hasTransactional = hasTransactional;
    }

    public Method getMethod() {
        return method;
    }

    public void setMethod(Method method) {
        this.method = method;
    }

    public boolean isHasTransactional() {
        return hasTransactional;
    }

    public void setHasTransactional(boolean hasTransactional) {
        this.hasTransactional = hasTransactional;
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
