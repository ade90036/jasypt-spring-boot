package com.ulisesbocchio.jasyptspringboot.encryptor;

import com.ulisesbocchio.jasyptspringboot.util.Singleton;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.BeanFactory;
import org.springframework.core.env.Environment;

import java.util.Optional;

import static com.ulisesbocchio.jasyptspringboot.util.Functional.tap;

/**
 * Default Lazy Encryptor that delegates to a custom {@link StringEncryptor} bean or creates a default {@link PooledPBEStringEncryptor}
 *
 * @author Ulises Bocchio
 */
@Slf4j
public class DefaultLazyEncryptor implements StringEncryptor {

    private final Singleton<StringEncryptor> singleton;

    public DefaultLazyEncryptor(final Environment e, final String customEncryptorBeanName, final BeanFactory bf) {
        singleton = new Singleton<>(() ->
                Optional.of(customEncryptorBeanName)
                        .filter(bf::containsBean)
                        .map(name -> (StringEncryptor) bf.getBean(name))
                        .map(tap(bean -> log.info("Found Custom Encryptor Bean {} with name: {}", bean, customEncryptorBeanName)))
                        .orElseGet(() -> {
                            log.info("String Encryptor custom Bean not found with name '{}'. Initializing Default String Encryptor", customEncryptorBeanName);
                            return createDefault(e);
                        }));
    }

    public DefaultLazyEncryptor(final Environment e) {
        singleton = new Singleton<>(() -> createDefault(e));
    }

    private StringEncryptor createDefault(Environment e) {
        String password = getRequiredProperty(e, "jasypt.encryptor.password");
        String algorithm = getProperty(e, "jasypt.encryptor.algorithm", "PBEWithMD5AndDES");
        Integer saltSize = Integer.parseInt(getProperty(e, "jasypt.encryptor.saltSize", "8"));
        Integer keyIterations = Integer.parseInt(getProperty(e, "jasypt.encryptor.keyIterations", "20"));



        try {
            return new DefaultStringEncryptor(algorithm, password, saltSize, keyIterations);
        } catch (Exception ex) {
            throw new RuntimeException(ex.getMessage(), ex);
        }
    }

    private static String getProperty(Environment environment, String key, String defaultValue) {
        if (!propertyExists(environment, key)) {
            log.info("Encryptor config not found for property {}, using default value: {}", key, defaultValue);
        }
        return environment.getProperty(key, defaultValue);
    }

    private static boolean propertyExists(final Environment environment, final String key) {
        return environment.getProperty(key) != null;
    }

    private static String getRequiredProperty(final Environment environment, final String key) {
        if (!propertyExists(environment, key)) {
            throw new IllegalStateException(String.format("Required Encryption configuration property missing: %s", key));
        }
        return environment.getProperty(key);
    }

    @Override
    public String encrypt(String message) throws Exception {
        return singleton.get().encrypt(message);
    }

    @Override
    public String decrypt(String encryptedMessage) throws Exception {
        return singleton.get().decrypt(encryptedMessage);
    }

}
