/*
 * Camel ApiMethod Enumeration generated by camel-api-component-maven-plugin
 */
package org.apache.camel.component.braintree.internal;

import java.lang.reflect.Method;
import java.util.List;

import com.braintreegateway.TransactionGateway;

import org.apache.camel.support.component.ApiMethod;
import org.apache.camel.support.component.ApiMethodArg;
import org.apache.camel.support.component.ApiMethodImpl;

import static org.apache.camel.support.component.ApiMethodArg.arg;
import static org.apache.camel.support.component.ApiMethodArg.setter;

/**
 * Camel {@link ApiMethod} Enumeration for com.braintreegateway.TransactionGateway
 */
public enum TransactionGatewayApiMethod implements ApiMethod {

    ADJUST_AUTHORIZATION(
        com.braintreegateway.Result.class,
        "adjustAuthorization",
        arg("id", String.class),
        arg("amount", java.math.BigDecimal.class)),

    ADJUST_AUTHORIZATION_1(
        com.braintreegateway.Result.class,
        "adjustAuthorization",
        arg("id", String.class),
        arg("request", com.braintreegateway.TransactionRequest.class)),

    CANCEL_RELEASE(
        com.braintreegateway.Result.class,
        "cancelRelease",
        arg("id", String.class)),

    CLONE_TRANSACTION(
        com.braintreegateway.Result.class,
        "cloneTransaction",
        arg("id", String.class),
        arg("cloneRequest", com.braintreegateway.TransactionCloneRequest.class)),

    CREDIT(
        com.braintreegateway.Result.class,
        "credit",
        arg("request", com.braintreegateway.TransactionRequest.class)),

    FIND(
        com.braintreegateway.Transaction.class,
        "find",
        arg("id", String.class)),

    PACKAGE_TRACKING(
        com.braintreegateway.Result.class,
        "packageTracking",
        arg("id", String.class),
        arg("packageTrackingRequest", com.braintreegateway.PackageTrackingRequest.class)),

    REFUND(
        com.braintreegateway.Result.class,
        "refund",
        arg("id", String.class)),

    REFUND_1(
        com.braintreegateway.Result.class,
        "refund",
        arg("id", String.class),
        arg("amount", java.math.BigDecimal.class)),

    REFUND_2(
        com.braintreegateway.Result.class,
        "refund",
        arg("id", String.class),
        arg("refundRequest", com.braintreegateway.TransactionRefundRequest.class)),

    RELEASE_FROM_ESCROW(
        com.braintreegateway.Result.class,
        "releaseFromEscrow",
        arg("id", String.class)),

    SALE(
        com.braintreegateway.Result.class,
        "sale",
        arg("request", com.braintreegateway.TransactionRequest.class)),

    SEARCH(
        com.braintreegateway.ResourceCollection.class,
        "search",
        arg("query", com.braintreegateway.TransactionSearchRequest.class)),

    SUBMIT_FOR_PARTIAL_SETTLEMENT(
        com.braintreegateway.Result.class,
        "submitForPartialSettlement",
        arg("id", String.class),
        arg("amount", java.math.BigDecimal.class)),

    SUBMIT_FOR_PARTIAL_SETTLEMENT_1(
        com.braintreegateway.Result.class,
        "submitForPartialSettlement",
        arg("id", String.class),
        arg("request", com.braintreegateway.TransactionRequest.class)),

    SUBMIT_FOR_SETTLEMENT(
        com.braintreegateway.Result.class,
        "submitForSettlement",
        arg("id", String.class)),

    SUBMIT_FOR_SETTLEMENT_1(
        com.braintreegateway.Result.class,
        "submitForSettlement",
        arg("id", String.class),
        arg("amount", java.math.BigDecimal.class)),

    SUBMIT_FOR_SETTLEMENT_2(
        com.braintreegateway.Result.class,
        "submitForSettlement",
        arg("id", String.class),
        arg("request", com.braintreegateway.TransactionRequest.class)),

    UPDATE_CUSTOM_FIELDS(
        com.braintreegateway.Result.class,
        "updateCustomFields",
        arg("id", String.class),
        arg("request", com.braintreegateway.TransactionRequest.class)),

    UPDATE_DETAILS(
        com.braintreegateway.Result.class,
        "updateDetails",
        arg("id", String.class),
        arg("request", com.braintreegateway.TransactionRequest.class)),

    VOID_TRANSACTION(
        com.braintreegateway.Result.class,
        "voidTransaction",
        arg("id", String.class));

    private final ApiMethod apiMethod;

    TransactionGatewayApiMethod(Class<?> resultType, String name, ApiMethodArg... args) {
        this.apiMethod = new ApiMethodImpl(TransactionGateway.class, resultType, name, args);
    }

    @Override
    public String getName() { return apiMethod.getName(); }

    @Override
    public Class<?> getResultType() { return apiMethod.getResultType(); }

    @Override
    public List<String> getArgNames() { return apiMethod.getArgNames(); }

    @Override
    public List<String> getSetterArgNames() { return apiMethod.getSetterArgNames(); }

    @Override
    public List<Class<?>> getArgTypes() { return apiMethod.getArgTypes(); }

    @Override
    public Method getMethod() { return apiMethod.getMethod(); }
}
