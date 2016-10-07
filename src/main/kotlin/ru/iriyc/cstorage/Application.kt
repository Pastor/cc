package ru.iriyc.cstorage

import lombok.extern.slf4j.Slf4j
import org.hibernate.jpa.HibernatePersistenceProvider
import org.springframework.beans.factory.annotation.Autowired
import org.springframework.boot.SpringApplication
import org.springframework.boot.autoconfigure.SpringBootApplication
import org.springframework.boot.autoconfigure.web.HttpMessageConverters
import org.springframework.context.annotation.*
import org.springframework.core.env.Environment
import org.springframework.data.jpa.repository.config.EnableJpaRepositories
import org.springframework.http.converter.FormHttpMessageConverter
import org.springframework.jdbc.datasource.DriverManagerDataSource
import org.springframework.orm.jpa.JpaTransactionManager
import org.springframework.orm.jpa.LocalContainerEntityManagerFactoryBean
import org.springframework.orm.jpa.vendor.HibernateJpaVendorAdapter
import org.springframework.transaction.annotation.EnableTransactionManagement
import java.util.*
import javax.sql.DataSource

interface Constants {
    companion object {
        const val STORAGE_HIBERNATE_DIALECT = "storage.hibernate.dialect"
        const val STORAGE_HIBERNATE_DDL = "storage.hibernate.ddl"
        const val STORAGE_HIBERNATE_SHOW_SQL = "storage.hibernate.sow_sql"
        const val STORAGE_JPA_PACKAGES_SCAN = "storage.jpa.packages_scan"
        const val STORAGE_JDBC_URL = "storage.jdbc.url"
        const val STORAGE_JDBC_DRIVER = "storage.jdbc.driver_class"
        const val STORAGE_JDBC_USERNAME = "storage.jdbc.username"
        const val STORAGE_JDBC_PASSWORD = "storage.jdbc.password"
    }
}

@Slf4j
@Configuration
@EnableTransactionManagement
@EnableJpaRepositories(
        basePackages = arrayOf("ru.iriyc.cstorage.repository"),
        basePackageClasses = arrayOf(),
        entityManagerFactoryRef = "emFactory",
        transactionManagerRef = "emTransactionManager")
open class ApplicationConfiguration @Autowired constructor(val environment: Environment) {
    @Bean(name = arrayOf("dataSource"))
    @Primary
    open fun dataSource(): DataSource {
        val dataSource = DriverManagerDataSource()
        dataSource.setDriverClassName(environment.getProperty(Constants.STORAGE_JDBC_DRIVER))
        dataSource.username = environment.getProperty(Constants.STORAGE_JDBC_USERNAME)
        dataSource.password = environment.getProperty(Constants.STORAGE_JDBC_PASSWORD)
        dataSource.url = environment.getProperty(Constants.STORAGE_JDBC_URL)
        return dataSource
    }

    @Bean(name = arrayOf("emFactory"))
    @DependsOn("dataSource")
    open fun entityManagerFactory(): LocalContainerEntityManagerFactoryBean {
        val emFactory = LocalContainerEntityManagerFactoryBean()
        emFactory.dataSource = dataSource()
        emFactory.setPersistenceProviderClass(HibernatePersistenceProvider::class.java)
        val vendorAdapter = HibernateJpaVendorAdapter()
        vendorAdapter.setGenerateDdl(true)
        emFactory.jpaVendorAdapter = vendorAdapter
        val properties = Properties()
        properties.setProperty("hibernate.dialect", environment.getProperty(Constants.STORAGE_HIBERNATE_DIALECT))
        properties.setProperty("hibernate.hbm2ddl.auto", environment.getProperty(Constants.STORAGE_HIBERNATE_DDL))
        properties.setProperty("hibernate.show_sql", environment.getProperty(Constants.STORAGE_HIBERNATE_SHOW_SQL))
        emFactory.setJpaProperties(properties)
        emFactory.setPackagesToScan(environment.getProperty(Constants.STORAGE_JPA_PACKAGES_SCAN))
        return emFactory
    }

    @Bean(name = arrayOf("emTransactionManager"))
    @DependsOn("emFactory")
    @Primary
    open fun transactionManager(): JpaTransactionManager {
        val transactionManager = JpaTransactionManager()
        transactionManager.entityManagerFactory = entityManagerFactory().`object`
        return transactionManager
    }

    @Bean
    open fun customConverters(): HttpMessageConverters {
        return HttpMessageConverters(FormHttpMessageConverter())
    }
}

@SpringBootApplication
@Import(ApplicationConfiguration::class)
open class Application {

}

fun main(args: Array<String>): Unit {
    SpringApplication.run(Application::class.java)
}