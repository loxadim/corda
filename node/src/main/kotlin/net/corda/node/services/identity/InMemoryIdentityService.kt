package net.corda.node.services.identity

import net.corda.core.contracts.PartyAndReference
import net.corda.core.crypto.AnonymousParty
import net.corda.core.crypto.CompositeKey
import net.corda.core.crypto.Party
import net.corda.core.node.services.IdentityService
import net.corda.core.serialization.SingletonSerializeAsToken
import java.security.cert.CertPath
import java.security.cert.Certificate
import java.util.*
import java.util.concurrent.ConcurrentHashMap
import javax.annotation.concurrent.ThreadSafe

/**
 * Simple identity service which caches parties and provides functionality for efficient lookup.
 */
@ThreadSafe
class InMemoryIdentityService() : SingletonSerializeAsToken(), IdentityService {
    private val keyToParties = ConcurrentHashMap<CompositeKey, Party>()
    private val nameToParties = ConcurrentHashMap<String, Party>()
    private val partyToPath = ConcurrentHashMap<AnonymousParty, CertPath>()

    override fun registerIdentity(party: Party) {
        keyToParties[party.owningKey] = party
        nameToParties[party.name] = party
    }

    // We give the caller a copy of the data set to avoid any locking problems
    override fun getAllIdentities(): Iterable<Party> = ArrayList(keyToParties.values)

    override fun partyFromKey(key: CompositeKey): Party? = keyToParties[key]
    override fun partyFromName(name: String): Party? = nameToParties[name]
    override fun partyFromAnonymous(party: AnonymousParty): Party? = partyFromKey(party.owningKey)
    override fun partyFromAnonymous(partyRef: PartyAndReference) = partyFromAnonymous(partyRef.party)

    override fun assertOwnership(party: Party, anonymousParty: AnonymousParty) {
        throw UnsupportedOperationException("not implemented")
    }

    override fun pathForAnonymous(anonymousParty: AnonymousParty): CertPath? {
        throw UnsupportedOperationException("not implemented")
    }

    override fun registerPath(party: Party, anonymousParty: AnonymousParty, path: CertPath) {
        var previousCertificate: Certificate? = null
        for (cert in path.certificates) {
            if (previousCertificate == null) {
                val expectedAnonymousPartyKey = cert.publicKey
                require(expectedAnonymousPartyKey is CompositeKey.Wrapper
                        && expectedAnonymousPartyKey.compositeKey == anonymousParty.owningKey)
            } else {
                cert.verify(previousCertificate.publicKey)
            }
            previousCertificate = cert
        }
        val expectedPartyKey = previousCertificate?.publicKey
        require(expectedPartyKey is CompositeKey.Wrapper
                && expectedPartyKey.compositeKey == party.owningKey)

        partyToPath[anonymousParty] == path
    }
}
