/*
 * Licensed to the Apache Software Foundation (ASF) under one or more
 * contributor license agreements.  See the NOTICE file distributed with
 * this work for additional information regarding copyright ownership.
 * The ASF licenses this file to You under the Apache License, Version 2.0
 * (the "License"); you may not use this file except in compliance with
 * the License.  You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.apache.camel.language.simple;

import java.security.MessageDigest;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Date;
import java.util.Iterator;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Random;
import java.util.concurrent.atomic.AtomicReference;
import java.util.regex.Pattern;

import org.apache.camel.CamelContext;
import org.apache.camel.CamelExecutionException;
import org.apache.camel.Exchange;
import org.apache.camel.ExchangePropertyKey;
import org.apache.camel.Expression;
import org.apache.camel.InvalidPayloadException;
import org.apache.camel.Predicate;
import org.apache.camel.spi.ClassResolver;
import org.apache.camel.spi.ExchangeFormatter;
import org.apache.camel.spi.Language;
import org.apache.camel.spi.UuidGenerator;
import org.apache.camel.support.CamelContextHelper;
import org.apache.camel.support.ClassicUuidGenerator;
import org.apache.camel.support.DefaultUuidGenerator;
import org.apache.camel.support.ExchangeHelper;
import org.apache.camel.support.ExpressionAdapter;
import org.apache.camel.support.LanguageHelper;
import org.apache.camel.support.MessageHelper;
import org.apache.camel.support.RandomUuidGenerator;
import org.apache.camel.support.ShortUuidGenerator;
import org.apache.camel.support.SimpleUuidGenerator;
import org.apache.camel.support.builder.ExpressionBuilder;
import org.apache.camel.util.FileUtil;
import org.apache.camel.util.ObjectHelper;
import org.apache.camel.util.OgnlHelper;
import org.apache.camel.util.SkipIterator;
import org.apache.camel.util.StringHelper;

/**
 * Expression builder used by the simple language.
 */
public final class SimpleExpressionBuilder {

    private static final Pattern OFFSET_PATTERN = Pattern.compile("([+-])([^+-]+)");

    private SimpleExpressionBuilder() {
    }

    /**
     * Returns the expression for the exchanges inbound message header invoking methods defined in a simple OGNL
     * notation
     *
     * @param ognl methods to invoke on the header in a simple OGNL syntax
     */
    public static Expression headersOgnlExpression(final String ognl) {
        return new KeyedOgnlExpressionAdapter(
                ognl, "headerOgnl(" + ognl + ")",
                (exchange, exp) -> {
                    String text = exp.evaluate(exchange, String.class);
                    return exchange.getIn().getHeader(text);
                });
    }

    /**
     * Returns the expression for the variable invoking methods defined in a simple OGNL notation
     *
     * @param ognl methods to invoke on the variable in a simple OGNL syntax
     */
    public static Expression variablesOgnlExpression(final String ognl) {
        return new KeyedOgnlExpressionAdapter(
                ognl, "variableOgnl(" + ognl + ")",
                (exchange, exp) -> {
                    String text = exp.evaluate(exchange, String.class);
                    return ExchangeHelper.getVariable(exchange, text);
                });
    }

    /**
     * Returns the message history (including exchange details or not)
     */
    public static Expression messageHistoryExpression(final boolean detailed) {
        return new ExpressionAdapter() {

            private ExchangeFormatter formatter;

            @Override
            public void init(CamelContext context) {
                if (detailed) {
                    // use the exchange formatter to log exchange details
                    formatter = getOrCreateExchangeFormatter(context);
                }
            }

            @Override
            public Object evaluate(Exchange exchange) {
                return MessageHelper.dumpMessageHistoryStacktrace(exchange, formatter, false);
            }

            private ExchangeFormatter getOrCreateExchangeFormatter(CamelContext camelContext) {
                return LanguageHelper.getOrCreateExchangeFormatter(camelContext, formatter);
            }

            @Override
            public String toString() {
                return "messageHistory(" + detailed + ")";
            }
        };
    }

    /**
     * Returns an iterator to collate (iterate) the given expression
     */
    public static Expression collateExpression(final String expression, final int group) {
        return new ExpressionAdapter() {
            private Expression exp;

            @Override
            public void init(CamelContext context) {
                // first use simple then create the group expression
                exp = context.resolveLanguage("simple").createExpression(expression);
                exp.init(context);
                exp = ExpressionBuilder.groupIteratorExpression(exp, null, Integer.toString(group), false);
                exp.init(context);
            }

            @Override
            public Object evaluate(Exchange exchange) {
                return exp.evaluate(exchange, Object.class);
            }

            @Override
            public String toString() {
                return "collate(" + expression + "," + group + ")";
            }
        };
    }

    /**
     * Returns an iterator to skip (iterate) the given expression
     */
    public static Expression skipExpression(final String expression, final int number) {
        return new ExpressionAdapter() {
            private Expression exp;

            @Override
            public void init(CamelContext context) {
                exp = context.resolveLanguage("simple").createExpression(expression);
                exp.init(context);
            }

            @Override
            public Object evaluate(Exchange exchange) {
                return skipIteratorExpression(exp, number).evaluate(exchange, Object.class);
            }

            @Override
            public String toString() {
                return "skip(" + expression + "," + number + ")";
            }
        };
    }

    /**
     * A ternary condition expression
     */
    public static Expression iifExpression(final String predicate, final String trueValue, final String falseValue) {
        return new ExpressionAdapter() {
            private Predicate pred;
            private Expression expTrue;
            private Expression expFalse;

            @Override
            public void init(CamelContext context) {
                pred = context.resolveLanguage("simple").createPredicate(predicate);
                pred.init(context);
                expTrue = context.resolveLanguage("simple").createExpression(trueValue);
                expTrue.init(context);
                expFalse = context.resolveLanguage("simple").createExpression(falseValue);
                expFalse.init(context);
            }

            @Override
            public Object evaluate(Exchange exchange) {
                if (pred.matches(exchange)) {
                    return expTrue.evaluate(exchange, Object.class);
                } else {
                    return expFalse.evaluate(exchange, Object.class);
                }
            }

            @Override
            public String toString() {
                return "iif(" + predicate + "," + trueValue + "," + falseValue + ")";
            }
        };
    }

    /**
     * An expression that creates an ArrayList
     */
    public static Expression listExpression(String[] values) {
        return new ExpressionAdapter() {

            private final Expression[] exps = new Expression[values != null ? values.length : 0];

            @Override
            public void init(CamelContext context) {
                for (int i = 0; values != null && i < values.length; i++) {
                    Expression exp = context.resolveLanguage("simple").createExpression(values[i]);
                    exp.init(context);
                    exps[i] = exp;
                }
            }

            @Override
            public Object evaluate(Exchange exchange) {
                List<Object> answer = new ArrayList<>(values != null ? values.length : 0);
                for (Expression exp : exps) {
                    Object val = exp.evaluate(exchange, Object.class);
                    answer.add(val);
                }
                return answer;
            }

            @Override
            public String toString() {
                return "list(" + Arrays.toString(values) + ")";
            }
        };
    }

    /**
     * An expression that creates an LinkedHashMap
     */
    public static Expression mapExpression(String[] pairs) {
        return new ExpressionAdapter() {

            private final Expression[] keys = new Expression[pairs != null ? pairs.length / 2 : 0];
            private final Expression[] values = new Expression[pairs != null ? pairs.length / 2 : 0];

            @Override
            public void init(CamelContext context) {
                for (int i = 0, j = 0; pairs != null && i < pairs.length - 1; j++) {
                    String key = pairs[i];
                    String value = pairs[i + 1];
                    Expression exp = context.resolveLanguage("simple").createExpression(key);
                    exp.init(context);
                    keys[j] = exp;
                    exp = context.resolveLanguage("simple").createExpression(value);
                    exp.init(context);
                    values[j] = exp;
                    i = i + 2;
                }
            }

            @Override
            public Object evaluate(Exchange exchange) {
                Map<String, Object> answer = new LinkedHashMap<>(keys.length);
                for (int i = 0; i < keys.length; i++) {
                    String key = keys[i].evaluate(exchange, String.class);
                    Object val = values[i].evaluate(exchange, Object.class);
                    answer.put(key, val);
                }
                return answer;
            }

            @Override
            public String toString() {
                return "map(" + Arrays.toString(values) + ")";
            }
        };
    }

    /**
     * Joins together the values from the expression
     */
    public static Expression joinExpression(final String expression, final String separator, final String prefix) {
        return new ExpressionAdapter() {
            private Expression exp;

            @Override
            public void init(CamelContext context) {
                exp = context.resolveLanguage("simple").createExpression(expression);
                exp.init(context);
                exp = ExpressionBuilder.joinExpression(exp, separator, prefix);
                exp.init(context);
            }

            @Override
            public Object evaluate(Exchange exchange) {
                return exp.evaluate(exchange, Object.class);
            }

            @Override
            public String toString() {
                if (prefix != null) {
                    return "join(" + expression + "," + separator + "," + prefix + ")";
                } else {
                    return "join(" + expression + "," + separator + ")";
                }
            }
        };
    }

    /**
     * Replaces string values from the expression
     */
    public static Expression replaceExpression(final String expression, final String from, final String to) {
        return new ExpressionAdapter() {
            private Expression exp;

            @Override
            public void init(CamelContext context) {
                exp = context.resolveLanguage("simple").createExpression(expression);
                exp.init(context);
                exp = ExpressionBuilder.replaceAll(exp, from, to);
                exp.init(context);
            }

            @Override
            public Object evaluate(Exchange exchange) {
                return exp.evaluate(exchange, Object.class);
            }

            @Override
            public String toString() {
                return "replace(" + expression + "," + from + "," + to + ")";
            }
        };
    }

    /**
     * Substring string values from the expression
     */
    public static Expression substringExpression(final String expression, final String head, final String tail) {
        return new ExpressionAdapter() {
            private Expression exp;
            private Expression exp1;
            private Expression exp2;

            @Override
            public void init(CamelContext context) {
                exp = context.resolveLanguage("simple").createExpression(expression);
                exp.init(context);
                exp1 = ExpressionBuilder.simpleExpression(head);
                exp1.init(context);
                exp2 = ExpressionBuilder.simpleExpression(tail);
                exp2.init(context);
            }

            @Override
            public Object evaluate(Exchange exchange) {
                int num1 = exp1.evaluate(exchange, Integer.class);
                int num2 = exp2.evaluate(exchange, Integer.class);
                if (num1 < 0 && num2 == 0) {
                    // if there is only one value and its negative then we want to clip from tail
                    num2 = num1;
                    num1 = 0;
                }
                num1 = Math.abs(num1);
                num2 = Math.abs(num2);
                return ExpressionBuilder.substring(exp, num1, num2).evaluate(exchange, Object.class);
            }

            @Override
            public String toString() {
                return "substring(" + expression + "," + head + "," + tail + ")";
            }
        };
    }

    /**
     * Hashes the value using the given algorithm
     */
    public static Expression hashExpression(final String expression, final String algorithm) {
        return new ExpressionAdapter() {
            private Expression exp;

            @Override
            public void init(CamelContext context) {
                exp = context.resolveLanguage("simple").createExpression(expression);
                exp.init(context);
            }

            @Override
            public Object evaluate(Exchange exchange) {
                byte[] data = exp.evaluate(exchange, byte[].class);
                if (data != null && data.length > 0) {
                    try {
                        MessageDigest digest = MessageDigest.getInstance(algorithm);
                        byte[] bytes = digest.digest(data);
                        return StringHelper.bytesToHex(bytes);
                    } catch (Exception e) {
                        throw CamelExecutionException.wrapCamelExecutionException(exchange, e);
                    }
                }
                return null;
            }

            @Override
            public String toString() {
                return "hash(" + expression + "," + algorithm + ")";
            }
        };
    }

    /**
     * Returns a random number between min and max (exclusive)
     */
    public static Expression randomExpression(final String min, final String max) {
        return new ExpressionAdapter() {
            private Expression exp1;
            private Expression exp2;

            @Override
            public Object evaluate(Exchange exchange) {
                int num1 = exp1.evaluate(exchange, Integer.class);
                int num2 = exp2.evaluate(exchange, Integer.class);
                Random random = new Random(); // NOSONAR
                return random.nextInt(num2 - num1) + num1;
            }

            @Override
            public void init(CamelContext context) {
                exp1 = ExpressionBuilder.simpleExpression(min);
                exp1.init(context);
                exp2 = ExpressionBuilder.simpleExpression(max);
                exp2.init(context);
            }

            @Override
            public String toString() {
                return "random(" + min + "," + max + ")";
            }
        };
    }

    /**
     * Returns a random number between 0 and max (exclusive)
     */
    public static Expression randomExpression(final int max) {
        return randomExpression(0, max);
    }

    /**
     * Returns a random number between min and max (exclusive)
     */
    public static Expression randomExpression(final int min, final int max) {
        return new ExpressionAdapter() {
            @Override
            public Object evaluate(Exchange exchange) {
                Random random = new Random(); // NOSONAR
                return random.nextInt(max - min) + min;
            }

            @Override
            public String toString() {
                return "random(" + min + "," + max + ")";
            }
        };
    }

    /**
     * Returns a new empty object of the given type
     */
    public static Expression newEmptyExpression(final String type) {

        return new ExpressionAdapter() {
            @Override
            public Object evaluate(Exchange exchange) {
                if ("map".equalsIgnoreCase(type)) {
                    return new LinkedHashMap<>();
                } else if ("string".equalsIgnoreCase(type)) {
                    return "";
                } else if ("list".equalsIgnoreCase(type)) {
                    return new ArrayList<>();
                }
                throw new IllegalArgumentException("function empty(%s) has unknown type".formatted(type));
            }

            @Override
            public String toString() {
                return "empty(%s)".formatted(type);
            }
        };
    }

    /**
     * Returns an uuid string based on the given generator (default, classic, short, simple)
     */
    public static Expression uuidExpression(final String generator) {
        return new ExpressionAdapter() {

            UuidGenerator uuid;

            @Override
            public Object evaluate(Exchange exchange) {
                return uuid.generateUuid();
            }

            @Override
            public void init(CamelContext context) {
                if ("classic".equalsIgnoreCase(generator)) {
                    uuid = new ClassicUuidGenerator();
                } else if ("short".equals(generator)) {
                    uuid = new ShortUuidGenerator();
                } else if ("simple".equals(generator)) {
                    uuid = new SimpleUuidGenerator();
                } else if ("random".equals(generator)) {
                    uuid = new RandomUuidGenerator();
                } else if (generator == null || "default".equals(generator)) {
                    uuid = new DefaultUuidGenerator();
                } else {
                    // lookup custom generator
                    uuid = CamelContextHelper.mandatoryLookup(context, generator, UuidGenerator.class);
                }
            }

            @Override
            public String toString() {
                if (generator != null) {
                    return "uuid(" + generator + ")";
                } else {
                    return "uuid";
                }
            }
        };
    }

    public static Expression fileNameExpression() {
        return new ExpressionAdapter() {
            @Override
            public Object evaluate(Exchange exchange) {
                return exchange.getIn().getHeader(Exchange.FILE_NAME, String.class);
            }

            @Override
            public String toString() {
                return "file:name";
            }
        };
    }

    public static Expression fileOnlyNameExpression() {
        return new ExpressionAdapter() {
            @Override
            public Object evaluate(Exchange exchange) {
                String answer = exchange.getIn().getHeader(Exchange.FILE_NAME_ONLY, String.class);
                if (answer == null) {
                    answer = exchange.getIn().getHeader(Exchange.FILE_NAME, String.class);
                    answer = FileUtil.stripPath(answer);
                }
                return answer;
            }

            @Override
            public String toString() {
                return "file:onlyname";
            }
        };
    }

    public static Expression fileNameNoExtensionExpression() {
        return new ExpressionAdapter() {
            @Override
            public Object evaluate(Exchange exchange) {
                String name = exchange.getIn().getHeader(Exchange.FILE_NAME, String.class);
                return FileUtil.stripExt(name);
            }

            @Override
            public String toString() {
                return "file:name.noext";
            }
        };
    }

    public static Expression fileNameNoExtensionSingleExpression() {
        return new ExpressionAdapter() {
            @Override
            public Object evaluate(Exchange exchange) {
                String name = exchange.getIn().getHeader(Exchange.FILE_NAME, String.class);
                return FileUtil.stripExt(name, true);
            }

            @Override
            public String toString() {
                return "file:name.noext.single";
            }
        };
    }

    public static Expression fileOnlyNameNoExtensionExpression() {
        return new ExpressionAdapter() {
            @Override
            public Object evaluate(Exchange exchange) {
                String name = fileOnlyNameExpression().evaluate(exchange, String.class);
                return FileUtil.stripExt(name);
            }

            @Override
            public String toString() {
                return "file:onlyname.noext";
            }
        };
    }

    public static Expression fileOnlyNameNoExtensionSingleExpression() {
        return new ExpressionAdapter() {
            @Override
            public Object evaluate(Exchange exchange) {
                String name = fileOnlyNameExpression().evaluate(exchange, String.class);
                return FileUtil.stripExt(name, true);
            }

            @Override
            public String toString() {
                return "file:onlyname.noext.single";
            }
        };
    }

    public static Expression fileExtensionExpression() {
        return new ExpressionAdapter() {
            @Override
            public Object evaluate(Exchange exchange) {
                String name = exchange.getIn().getHeader(Exchange.FILE_NAME, String.class);
                return FileUtil.onlyExt(name);
            }

            @Override
            public String toString() {
                return "file:ext";
            }
        };
    }

    public static Expression fileExtensionSingleExpression() {
        return new ExpressionAdapter() {
            @Override
            public Object evaluate(Exchange exchange) {
                String name = exchange.getIn().getHeader(Exchange.FILE_NAME, String.class);
                return FileUtil.onlyExt(name, true);
            }

            @Override
            public String toString() {
                return "file:ext.single";
            }
        };
    }

    public static Expression fileParentExpression() {
        return new ExpressionAdapter() {
            @Override
            public Object evaluate(Exchange exchange) {
                return exchange.getIn().getHeader("CamelFileParent", String.class);
            }

            @Override
            public String toString() {
                return "file:parent";
            }
        };
    }

    public static Expression filePathExpression() {
        return new ExpressionAdapter() {
            @Override
            public Object evaluate(Exchange exchange) {
                return exchange.getIn().getHeader("CamelFilePath", String.class);
            }

            @Override
            public String toString() {
                return "file:path";
            }
        };
    }

    public static Expression fileAbsolutePathExpression() {
        return new ExpressionAdapter() {
            @Override
            public Object evaluate(Exchange exchange) {
                return exchange.getIn().getHeader("CamelFileAbsolutePath", String.class);
            }

            @Override
            public String toString() {
                return "file:absolute.path";
            }
        };
    }

    public static Expression fileAbsoluteExpression() {
        return new ExpressionAdapter() {
            @Override
            public Object evaluate(Exchange exchange) {
                return exchange.getIn().getHeader("CamelFileAbsolute", Boolean.class);
            }

            @Override
            public String toString() {
                return "file:absolute";
            }
        };
    }

    public static Expression fileSizeExpression() {
        return new ExpressionAdapter() {
            @Override
            public Object evaluate(Exchange exchange) {
                return exchange.getIn().getHeader(Exchange.FILE_LENGTH, Long.class);
            }

            @Override
            public String toString() {
                return "file:length";
            }
        };
    }

    public static Expression fileLastModifiedExpression() {
        return new ExpressionAdapter() {
            @Override
            public Object evaluate(Exchange exchange) {
                return exchange.getIn().getHeader(Exchange.FILE_LAST_MODIFIED, Long.class);
            }

            @Override
            public String toString() {
                return "file:modified";
            }
        };
    }

    public static Expression dateExpression(final String command) {
        return dateExpression(command, null, null);
    }

    public static Expression dateExpression(final String command, final String pattern) {
        return dateExpression(command, null, pattern);
    }

    public static Expression dateExpression(final String commandWithOffsets, final String timezone, final String pattern) {
        final String command = commandWithOffsets.split("[+-]", 2)[0].trim();
        final List<Long> offsets = LanguageHelper.captureOffsets(commandWithOffsets, OFFSET_PATTERN);

        return new ExpressionAdapter() {
            @Override
            public Object evaluate(Exchange exchange) {
                Date date = evalDate(exchange, command);

                return LanguageHelper.applyDateOffsets(date, offsets, pattern, timezone);
            }

            @Override
            public String toString() {
                if (timezone != null && pattern != null) {
                    return "date(" + commandWithOffsets + ":" + timezone + ":" + pattern + ")";
                } else if (pattern != null) {
                    return "date(" + commandWithOffsets + ":" + pattern + ")";
                } else {
                    return "date(" + commandWithOffsets + ")";
                }
            }
        };
    }

    private static Date evalDate(Exchange exchange, String command) {
        Date date;
        if ("now".equals(command)) {
            date = new Date();
        } else if ("exchangeCreated".equals(command)) {
            date = LanguageHelper.dateFromExchangeCreated(exchange);
        } else if (command.startsWith("header.")) {
            date = LanguageHelper.dateFromHeader(exchange, command, (e, o) -> tryConvertingAsDate(e, o, command));
        } else if (command.startsWith("variable.")) {
            date = LanguageHelper.dateFromVariable(exchange, command, (e, o) -> tryConvertingAsDate(e, o, command));
        } else if (command.startsWith("exchangeProperty.")) {
            date = LanguageHelper.dateFromExchangeProperty(exchange, command, (e, o) -> tryConvertingAsDate(e, o, command));
        } else if ("file".equals(command)) {
            date = LanguageHelper.dateFromFileLastModified(exchange, command);
        } else {
            throw new IllegalArgumentException("Command not supported for dateExpression: " + command);
        }
        return date;
    }

    private static Date tryConvertingAsDate(Exchange exchange, Object obj, String command) {
        final Date date = exchange.getContext().getTypeConverter().tryConvertTo(Date.class, exchange, obj);
        if (date == null) {
            throw new IllegalArgumentException("Cannot find Date/long object at command: " + command);
        }

        return date;
    }

    public static Expression skipIteratorExpression(final Expression expression, final int skip) {
        return new ExpressionAdapter() {
            @Override
            public Object evaluate(Exchange exchange) {
                // evaluate expression as iterator
                Iterator<?> it = expression.evaluate(exchange, Iterator.class);
                ObjectHelper.notNull(it,
                        "expression: " + expression + " evaluated on " + exchange + " must return an java.util.Iterator");
                return new SkipIterator(it, skip);
            }

            @Override
            public String toString() {
                return "skip " + expression + " " + skip + " times";
            }
        };
    }

    /**
     * Returns the expression for the {@code null} value
     */
    public static Expression nullExpression() {
        return new ExpressionAdapter() {
            @Override
            public Object evaluate(Exchange exchange) {
                return null;
            }

            @Override
            public String toString() {
                return "null";
            }
        };
    }

    /**
     * Returns the expression for the exchanges inbound message body converted to the given type and invoking methods on
     * the converted body defined in a simple OGNL notation
     */
    public static Expression mandatoryBodyOgnlExpression(final String name, final String ognl) {
        return new ExpressionAdapter() {
            private ClassResolver classResolver;
            private Expression exp;
            private Language bean;

            @Override
            public Object evaluate(Exchange exchange) {
                String text = exp.evaluate(exchange, String.class);
                Class<?> type;
                try {
                    type = classResolver.resolveMandatoryClass(text);
                } catch (ClassNotFoundException e) {
                    throw CamelExecutionException.wrapCamelExecutionException(exchange, e);
                }
                Object body;
                try {
                    body = exchange.getIn().getMandatoryBody(type);
                } catch (InvalidPayloadException e) {
                    throw CamelExecutionException.wrapCamelExecutionException(exchange, e);
                }
                Expression ognlExp = bean.createExpression(null, new Object[] { null, body, ognl });
                ognlExp.init(exchange.getContext());
                return ognlExp.evaluate(exchange, Object.class);
            }

            @Override
            public void init(CamelContext context) {
                classResolver = context.getClassResolver();
                exp = ExpressionBuilder.simpleExpression(name);
                exp.init(context);
                bean = context.resolveLanguage("bean");
            }

            @Override
            public String toString() {
                return "mandatoryBodyAs[" + name + "](" + ognl + ")";
            }
        };
    }

    /**
     * Returns the expression for the exchanges inbound message body converted to the given type
     */
    public static Expression mandatoryBodyExpression(final String name) {
        return new ExpressionAdapter() {
            private ClassResolver classResolver;
            private Expression exp;

            @Override
            public Object evaluate(Exchange exchange) {
                String text = exp.evaluate(exchange, String.class);
                Class<?> type;
                try {
                    type = classResolver.resolveMandatoryClass(text);
                } catch (ClassNotFoundException e) {
                    throw CamelExecutionException.wrapCamelExecutionException(exchange, e);
                }
                try {
                    return exchange.getIn().getMandatoryBody(type);
                } catch (InvalidPayloadException e) {
                    throw CamelExecutionException.wrapCamelExecutionException(exchange, e);
                }
            }

            @Override
            public void init(CamelContext context) {
                classResolver = context.getClassResolver();
                exp = ExpressionBuilder.simpleExpression(name);
                exp.init(context);
            }

            @Override
            public String toString() {
                return "mandatoryBodyAs[" + name + "]";
            }
        };
    }

    /**
     * Returns the expression for the message converted to the given type and invoking methods on the converted message
     * defined in a simple OGNL notation
     */
    public static Expression messageOgnlExpression(final String name, final String ognl) {
        return new ExpressionAdapter() {
            private ClassResolver classResolver;
            private Expression exp;
            private Language bean;

            @Override
            public Object evaluate(Exchange exchange) {
                String text = exp.evaluate(exchange, String.class);
                Class<?> type;
                try {
                    type = classResolver.resolveMandatoryClass(text);
                } catch (ClassNotFoundException e) {
                    throw CamelExecutionException.wrapCamelExecutionException(exchange, e);
                }
                Object msg = exchange.getMessage(type);
                if (msg != null) {
                    // ognl is able to evaluate method name if it contains nested functions
                    // so we should not eager evaluate ognl as a string
                    Expression ognlExp = bean.createExpression(null, new Object[] { null, msg, ognl });
                    ognlExp.init(exchange.getContext());
                    return ognlExp.evaluate(exchange, Object.class);
                } else {
                    return null;
                }
            }

            @Override
            public void init(CamelContext context) {
                classResolver = context.getClassResolver();
                exp = ExpressionBuilder.simpleExpression(name);
                exp.init(context);
                bean = context.resolveLanguage("bean");
            }

            @Override
            public String toString() {
                return "messageOgnlAs[" + name + "](" + ognl + ")";
            }
        };
    }

    /**
     * Returns the expression for the exchanges inbound message body converted to the given type and invoking methods on
     * the converted body defined in a simple OGNL notation
     */
    public static Expression bodyOgnlExpression(final String name, final String ognl) {
        return new ExpressionAdapter() {
            private ClassResolver classResolver;
            private Expression exp;
            private Language bean;

            @Override
            public Object evaluate(Exchange exchange) {
                String text = exp.evaluate(exchange, String.class);
                Class<?> type;
                try {
                    type = classResolver.resolveMandatoryClass(text);
                } catch (ClassNotFoundException e) {
                    throw CamelExecutionException.wrapCamelExecutionException(exchange, e);
                }
                Object body = exchange.getIn().getBody(type);
                if (body != null) {
                    // ognl is able to evaluate method name if it contains nested functions
                    // so we should not eager evaluate ognl as a string
                    Expression ognlExp = bean.createExpression(null, new Object[] { null, body, ognl });
                    ognlExp.init(exchange.getContext());
                    return ognlExp.evaluate(exchange, Object.class);
                } else {
                    return null;
                }
            }

            @Override
            public void init(CamelContext context) {
                classResolver = context.getClassResolver();
                exp = ExpressionBuilder.simpleExpression(name);
                exp.init(context);
                bean = context.resolveLanguage("bean");
            }

            @Override
            public String toString() {
                return "bodyOgnlAs[" + name + "](" + ognl + ")";
            }
        };
    }

    /**
     * Returns the expression for the exchange invoking methods defined in a simple OGNL notation
     *
     * @param ognl methods to invoke on the exchange in a simple OGNL syntax
     */
    public static Expression exchangeOgnlExpression(final String ognl) {
        return new ExpressionAdapter() {
            private Language bean;

            @Override
            public Object evaluate(Exchange exchange) {
                // ognl is able to evaluate method name if it contains nested functions
                // so we should not eager evaluate ognl as a string
                Expression ognlExp = bean.createExpression(null, new Object[] { null, exchange, ognl });
                ognlExp.init(exchange.getContext());
                return ognlExp.evaluate(exchange, Object.class);
            }

            @Override
            public void init(CamelContext context) {
                bean = context.resolveLanguage("bean");
            }

            @Override
            public String toString() {
                return "exchangeOgnl(" + ognl + ")";
            }
        };
    }

    /**
     * Returns the expression for the exchanges camelContext invoking methods defined in a simple OGNL notation
     *
     * @param ognl methods to invoke on the context in a simple OGNL syntax
     */
    public static Expression camelContextOgnlExpression(final String ognl) {
        return new ExpressionAdapter() {
            private Expression exp;

            @Override
            public void init(CamelContext context) {
                exp = ExpressionBuilder.beanExpression(context, ognl);
                exp.init(context);
            }

            @Override
            public Object evaluate(Exchange exchange) {
                // ognl is able to evaluate method name if it contains nested functions
                // so we should not eager evaluate ognl as a string
                return exp.evaluate(exchange, Object.class);
            }

            @Override
            public String toString() {
                return "camelContextOgnl(" + ognl + ")";
            }
        };
    }

    /**
     * Returns the expression for the exchanges inbound message body invoking methods defined in a simple OGNL notation
     *
     * @param ognl methods to invoke on the body in a simple OGNL syntax
     */
    public static Expression bodyOgnlExpression(final String ognl) {
        return new ExpressionAdapter() {
            private Language bean;

            @Override
            public Object evaluate(Exchange exchange) {
                Object body = exchange.getIn().getBody();
                if (body == null) {
                    return null;
                }
                Expression ognlExp = bean.createExpression(null, new Object[] { null, body, ognl });
                ognlExp.init(exchange.getContext());
                return ognlExp.evaluate(exchange, Object.class);
            }

            @Override
            public void init(CamelContext context) {
                bean = context.resolveLanguage("bean");
            }

            @Override
            public String toString() {
                return "bodyOgnl(" + ognl + ")";
            }
        };
    }

    /**
     * Returns an expression that caches the evaluation of another expression and returns the cached value, to avoid
     * re-evaluating the expression.
     *
     * @param  expression the target expression to cache
     * @return            the cached value
     */
    public static Expression cacheExpression(final Expression expression) {
        return new ExpressionAdapter() {
            private final AtomicReference<Object> cache = new AtomicReference<>();

            @Override
            public Object evaluate(Exchange exchange) {
                Object answer = cache.get();
                if (answer == null) {
                    answer = expression.evaluate(exchange, Object.class);
                    cache.set(answer);
                }
                return answer;
            }

            @Override
            public String toString() {
                return expression.toString();
            }
        };
    }

    /**
     * Returns an expression for a type value
     *
     * @param  name the type name
     * @return      an expression object which will return the type value
     */
    public static Expression typeExpression(final String name) {
        return new ExpressionAdapter() {
            private ClassResolver classResolver;
            private Expression exp;

            @Override
            public void init(CamelContext context) {
                classResolver = context.getClassResolver();
                exp = ExpressionBuilder.simpleExpression(name);
                exp.init(context);
            }

            @Override
            public Object evaluate(Exchange exchange) {
                // it may refer to a class type
                String text = exp.evaluate(exchange, String.class);
                Class<?> type = classResolver.resolveClass(text);
                if (type != null) {
                    return type;
                }

                int pos = text.lastIndexOf('.');
                if (pos > 0) {
                    String before = text.substring(0, pos);
                    String after = text.substring(pos + 1);
                    type = classResolver.resolveClass(before);
                    if (type != null) {
                        // special for enum constants
                        if (type.isEnum()) {
                            Class<Enum<?>> enumClass = (Class<Enum<?>>) type;
                            for (Enum<?> enumValue : enumClass.getEnumConstants()) {
                                if (enumValue.name().equalsIgnoreCase(after)) {
                                    return type.cast(enumValue);
                                }
                            }
                            throw CamelExecutionException.wrapCamelExecutionException(exchange,
                                    new ClassNotFoundException("Cannot find enum: " + after + " on type: " + type));
                        } else {
                            // we assume it is a field constant
                            Object answer = ObjectHelper.lookupConstantFieldValue(type, after);
                            if (answer != null) {
                                return answer;
                            }
                        }
                    }
                }

                throw CamelExecutionException.wrapCamelExecutionException(exchange,
                        new ClassNotFoundException("Cannot find type: " + text));
            }

            @Override
            public String toString() {
                return "type:" + name;
            }
        };
    }

    /**
     * Returns an expression for the property value of exchange with the given name invoking methods defined in a simple
     * OGNL notation
     *
     * @param ognl methods to invoke on the property in a simple OGNL syntax
     */
    public static Expression propertyOgnlExpression(final String ognl) {
        return new KeyedOgnlExpressionAdapter(
                ognl, "propertyOgnl(" + ognl + ")",
                (exchange, exp) -> {
                    String text = exp.evaluate(exchange, String.class);
                    return exchange.getProperty(text);
                });
    }

    /**
     * Returns the expression for the exchange's exception invoking methods defined in a simple OGNL notation
     *
     * @param ognl methods to invoke on the body in a simple OGNL syntax
     */
    public static Expression exchangeExceptionOgnlExpression(final String ognl) {
        return new ExpressionAdapter() {
            private Language bean;

            @Override
            public Object evaluate(Exchange exchange) {
                Object exception = exchange.getException();
                if (exception == null) {
                    exception = exchange.getProperty(ExchangePropertyKey.EXCEPTION_CAUGHT, Exception.class);
                }

                if (exception == null) {
                    return null;
                }

                // ognl is able to evaluate method name if it contains nested functions
                // so we should not eager evaluate ognl as a string
                Expression ognlExp = bean.createExpression(null, new Object[] { null, exception, ognl });
                ognlExp.init(exchange.getContext());
                return ognlExp.evaluate(exchange, Object.class);
            }

            @Override
            public void init(CamelContext context) {
                bean = context.resolveLanguage("bean");
            }

            @Override
            public String toString() {
                return "exchangeExceptionOgnl(" + ognl + ")";
            }
        };
    }

    /**
     * Expression adapter for OGNL expression from Message Header or Exchange property
     */
    public static class KeyedOgnlExpressionAdapter extends ExpressionAdapter {
        private final String ognl;
        private final String toStringValue;
        private final KeyedEntityRetrievalStrategy keyedEntityRetrievalStrategy;
        private String key;
        private final String method;
        private Expression keyExpression;
        private Expression ognlExpression;
        private Language beanLanguage;

        public KeyedOgnlExpressionAdapter(String ognl, String toStringValue,
                                          KeyedEntityRetrievalStrategy keyedEntityRetrievalStrategy) {
            this.ognl = ognl;
            this.toStringValue = toStringValue;
            this.keyedEntityRetrievalStrategy = keyedEntityRetrievalStrategy;

            // Split ognl except when this is not a Map, Array
            // and we would like to keep the dots within the key name
            List<String> methods = OgnlHelper.splitOgnl(ognl);

            key = methods.get(0);
            String keySuffix = "";
            // if ognl starts with a key inside brackets (eg: [foo.bar])
            // remove starting and ending brackets from key
            if (key.startsWith("[") && key.endsWith("]")) {
                key = StringHelper.removeLeadingAndEndingQuotes(key.substring(1, key.length() - 1));
                keySuffix = StringHelper.after(methods.get(0), key);
            }
            // remove any OGNL operators so we got the pure key name
            key = OgnlHelper.removeOperators(key);
            // and this may be the last remainder method to try as OGNL if there are no exchange properties with those key names
            method = StringHelper.after(ognl, key + keySuffix);
        }

        @Override
        public void init(CamelContext context) {
            beanLanguage = context.resolveLanguage("bean");
            ognlExpression = ExpressionBuilder.simpleExpression(ognl);
            ognlExpression.init(context);
            // key must be lazy eval as it only used in special situations
        }

        @Override
        public Object evaluate(Exchange exchange) {
            // try with full name first
            Object property = keyedEntityRetrievalStrategy.getKeyedEntity(exchange, ognlExpression);
            if (property != null) {
                return property;
            }

            // key must be lazy eval as it only used in special situations
            if (keyExpression == null) {
                keyExpression = ExpressionBuilder.simpleExpression(key);
                keyExpression.init(exchange.getContext());
            }

            property = keyedEntityRetrievalStrategy.getKeyedEntity(exchange, keyExpression);
            if (property == null) {
                return null;
            }
            if (method != null) {
                Expression exp = beanLanguage.createExpression(null, new Object[] { null, property, method });
                exp.init(exchange.getContext());
                return exp.evaluate(exchange, Object.class);
            } else {
                return property;
            }
        }

        @Override
        public String toString() {
            return toStringValue;
        }

        /**
         * Strategy to retrieve the value based on the key
         */
        public interface KeyedEntityRetrievalStrategy {
            Object getKeyedEntity(Exchange exchange, Expression key);
        }
    }
}
