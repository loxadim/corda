package net.corda.webserver

import com.google.common.net.HostAndPort
import net.corda.core.getOrThrow
import net.corda.core.node.NodeInfo
import net.corda.core.node.services.ServiceInfo
import net.corda.node.driver.driver
import net.corda.node.driver.addressMustBeBound
import net.corda.node.driver.addressMustNotBeBound
import net.corda.node.services.api.RegulatorService
import net.corda.node.services.messaging.ArtemisMessagingComponent
import net.corda.node.services.transactions.SimpleNotaryService
import org.junit.Test
import java.util.concurrent.Executors


class DriverTests {
    companion object {
        val executorService = Executors.newScheduledThreadPool(2)

        fun webserverMustBeUp(webserverAddr: HostAndPort) {
            addressMustBeBound(executorService, webserverAddr)
        }

        fun webserverMustBeDown(webserverAddr: HostAndPort) {
            addressMustNotBeBound(executorService, webserverAddr)
        }
    }

    @Test
    fun `starting a node and independent web server works`() {
        val addr = driver {
            val node = startNode("test").getOrThrow()
            val webserverAddr = startWebserver(node).getOrThrow()
            webserverMustBeUp(webserverAddr)
            webserverAddr
        }
        webserverMustBeDown(addr)
    }
}
