package ru.iriyc.cstorage;

import lombok.extern.slf4j.Slf4j;
import org.hibernate.jpa.HibernatePersistenceProvider;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.autoconfigure.web.HttpMessageConverters;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.DependsOn;
import org.springframework.context.annotation.Primary;
import org.springframework.core.env.Environment;
import org.springframework.data.jpa.repository.config.EnableJpaRepositories;
import org.springframework.http.converter.FormHttpMessageConverter;
import org.springframework.jdbc.datasource.DriverManagerDataSource;
import org.springframework.orm.jpa.JpaTransactionManager;
import org.springframework.orm.jpa.LocalContainerEntityManagerFactoryBean;
import org.springframework.orm.jpa.vendor.HibernateJpaVendorAdapter;
import org.springframework.transaction.annotation.EnableTransactionManagement;

import javax.sql.DataSource;
import java.util.Properties;

@Slf4j
@Configuration
@EnableTransactionManagement
@EnableJpaRepositories(
        basePackages = {"ru.iriyc.cstorage.repository"},
        basePackageClasses = {},
        entityManagerFactoryRef = "emFactory",
        transactionManagerRef = "emTransactionManager")

public class CryptStorageConfiguration {
    private final Environment environment;

    @Autowired
    public CryptStorageConfiguration(Environment environment) {
        this.environment = environment;
    }

    @Bean(name = "dataSource")
    @Primary
    public DataSource dataSource() {
        final DriverManagerDataSource dataSource = new DriverManagerDataSource();
        dataSource.setDriverClassName(environment.getProperty(Constants.STORAGE_JDBC_DRIVER));
        dataSource.setUsername(environment.getProperty(Constants.STORAGE_JDBC_USERNAME));
        dataSource.setPassword(environment.getProperty(Constants.STORAGE_JDBC_PASSWORD));
        dataSource.setUrl(environment.getProperty(Constants.STORAGE_JDBC_URL));
        return dataSource;
    }

    @Bean(name = "emFactory")
    @DependsOn("dataSource")
    public LocalContainerEntityManagerFactoryBean entityManagerFactory() {
        final LocalContainerEntityManagerFactoryBean emFactory = new LocalContainerEntityManagerFactoryBean();
        emFactory.setDataSource(dataSource());
        emFactory.setPersistenceProviderClass(HibernatePersistenceProvider.class);
        final HibernateJpaVendorAdapter vendorAdapter = new HibernateJpaVendorAdapter();
        vendorAdapter.setGenerateDdl(true);
        emFactory.setJpaVendorAdapter(vendorAdapter);
        final Properties properties = new Properties();
        properties.setProperty("hibernate.dialect", environment.getProperty(Constants.STORAGE_HIBERNATE_DIALECT));
        properties.setProperty("hibernate.hbm2ddl.auto", environment.getProperty(Constants.STORAGE_HIBERNATE_DDL));
        properties.setProperty("hibernate.show_sql", environment.getProperty(Constants.STORAGE_HIBERNATE_SHOW_SQL));
        emFactory.setJpaProperties(properties);
        emFactory.setPackagesToScan(environment.getProperty(Constants.STORAGE_JPA_PACKAGES_SCAN));
        return emFactory;
    }

    @Bean(name = "emTransactionManager")
    @DependsOn("emFactory")
    @Primary
    public JpaTransactionManager transactionManager() {
        final JpaTransactionManager transactionManager = new JpaTransactionManager();
        transactionManager.setEntityManagerFactory(entityManagerFactory().getObject());
        return transactionManager;
    }

    @Bean
    public HttpMessageConverters customConverters() {
        return new HttpMessageConverters(
                new FormHttpMessageConverter());
    }
}
