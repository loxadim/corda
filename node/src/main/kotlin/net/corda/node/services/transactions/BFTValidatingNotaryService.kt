package net.corda.node.services.transactions

import co.paralleluniverse.fibers.Suspendable
import com.google.common.net.HostAndPort
import net.corda.core.contracts.TransactionVerificationException
import net.corda.core.crypto.DigitalSignature
import net.corda.core.crypto.Party
import net.corda.core.flows.FlowLogic
import net.corda.core.node.services.TimestampChecker
import net.corda.core.serialization.deserialize
import net.corda.core.serialization.serialize
import net.corda.core.transactions.SignedTransaction
import net.corda.core.transactions.WireTransaction
import net.corda.core.utilities.loggerFor
import net.corda.core.utilities.unwrap
import net.corda.flows.NotaryError
import net.corda.flows.NotaryException
import net.corda.flows.ResolveTransactionsFlow
import net.corda.node.services.api.ServiceHubInternal
import org.jetbrains.exposed.sql.Database
import java.security.SignatureException
import kotlin.concurrent.thread

/**
 * A validating notary service operated by a group of parties that don't necessarily trust each other.
 *
 * A transaction is notarised when the consensus is reached by the cluster on its uniqueness and validity.
 */
class BFTValidatingNotaryService(val services: ServiceHubInternal,
                                 val timestampChecker: TimestampChecker,
                                 myAddress: HostAndPort,
                                 clusterAddresses: List<HostAndPort>,
                                 val db: Database,
                                 val client: BFTSMaRt.Client) : NotaryService(services) {
    init {
        require(myAddress in clusterAddresses) {
            "expected myAddress '$myAddress' to be listed in clusterAddresses '$clusterAddresses'"
        }
        startServerThread()
    }

    companion object {
        val type = ValidatingNotaryService.type.getSubType("bft")
        private val log = loggerFor<BFTValidatingNotaryService>()
    }

    private val serverId: Int = clusterAddresses.indexOf(myAddress)

    override fun createFlow(otherParty: Party) = ServiceFlow(otherParty, client)

    private fun startServerThread() {
        thread(name = "BFTSmartServer-$serverId", isDaemon = true) {
            Server(serverId, db, "bft_smart_notary_committed_states", services, timestampChecker)
        }
    }

    class ServiceFlow(val otherSide: Party, val client: BFTSMaRt.Client) : FlowLogic<Void?>() {

        @Suspendable
        override fun call(): Void? {
            val stx = receive<SignedTransaction>(otherSide).unwrap { it }
            val signatures = commit(stx)
            send(otherSide, signatures)
            return null
        }

        private fun commit(stx: SignedTransaction): List<DigitalSignature> {
            val response = client.commitTransaction(stx, otherSide)
            if (response is BFTSMaRt.ClusterResponse.Error) throw NotaryException(response.error)
            val signatures = (response as BFTSMaRt.ClusterResponse.Signatures).txSignatures

            log.debug("All input states of transaction ${stx.id} have been committed")
            return signatures
        }
    }

    class Server(id: Int, db: Database,
                 tableName: String,
                 services: ServiceHubInternal,
                 timestampChecker: TimestampChecker) : BFTSMaRt.Server(id, db, tableName, services, timestampChecker) {

        override fun executeCommand(command: ByteArray): ByteArray? {
            val request = command.deserialize<BFTSMaRt.CommitRequest>()
            val stx = request.tx as SignedTransaction
            val response = verifyAndCommitTx(stx, request.callerIdentity)
            return response.serialize().bytes
        }

        fun verifyAndCommitTx(stx: SignedTransaction, callerIdentity: Party): BFTSMaRt.ReplicaResponse {
            val response = try {
                checkSignatures(stx)

                val wtx = stx.tx
                validateTimestamp(wtx.timestamp)
                validateTransaction(wtx, callerIdentity)

                commitInputStates(wtx.inputs, wtx.id, callerIdentity)

                val sig = sign(wtx.id.bytes)
                BFTSMaRt.ReplicaResponse.Signature(sig)
            } catch (e: NotaryException) {
                BFTSMaRt.ReplicaResponse.Error(e.error)
            }
            return response
        }

        private fun checkSignatures(stx: SignedTransaction) {
            try {
                stx.verifySignatures(services.myInfo.notaryIdentity.owningKey)
            } catch(e: SignedTransaction.SignaturesMissingException) {
                throw NotaryException(NotaryError.SignaturesMissing(e))
            }
        }

        fun validateTransaction(wtx: WireTransaction, party: Party) {
            try {
                resolveTransaction(wtx, party)
                wtx.toLedgerTransaction(services).verify()
            } catch (e: Exception) {
                throw when (e) {
                    is TransactionVerificationException -> NotaryException(NotaryError.TransactionInvalid(e.toString()))
                    is SignatureException -> NotaryException(NotaryError.SignaturesInvalid(e.toString()))
                    else -> e
                }
            }
        }

        private fun resolveTransaction(wtx: WireTransaction, party: Party) {
            services.startFlow(ResolveTransactionsFlow(wtx, party)).resultFuture.get()
        }
    }
}
