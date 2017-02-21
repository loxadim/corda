package net.corda.core.node.services

import net.corda.core.contracts.PartyAndReference
import net.corda.core.crypto.AnonymousParty
import net.corda.core.crypto.CompositeKey
import net.corda.core.crypto.Party
import java.security.cert.CertPath

/**
 * An identity service maintains an bidirectional map of [Party]s to their associated public keys and thus supports
 * lookup of a party given its key. This is obviously very incomplete and does not reflect everything a real identity
 * service would provide.
 */
interface IdentityService {
    fun registerIdentity(party: Party)

    /**
     * Verify and then store the certificates proving that an anonymous party's key is owned by the given full
     * party.
     *
     * @throws IllegalArgumentException if the chain does not link the two parties, or if there is already an existing
     * certificate chain for the anonymous party. Anonymous parties must always resolve to a single owning party.
     */
    @Throws(IllegalArgumentException::class)
    fun registerPath(party: Party, anonymousParty: AnonymousParty, path: CertPath)

    /**
     * Asserts that an anonymous party maps to the given full party, by looking up the certificate chain associated with
     * the anonymous party and resolving it back to the given full party.
     *
     * @throws IllegalStateException if the anonymous party is not owned by the full party.
     */
    @Throws(IllegalStateException::class)
    fun assertOwnership(party: Party, anonymousParty: AnonymousParty)

    /**
     * Get all identities known to the service. This is expensive, and [partyFromKey] or [partyFromName] should be
     * used in preference where possible.
     */
    fun getAllIdentities(): Iterable<Party>

    // There is no method for removing identities, as once we are made aware of a Party we want to keep track of them
    // indefinitely. It may be that in the long term we need to drop or archive very old Party information for space,
    // but for now this is not supported.

    fun partyFromKey(key: CompositeKey): Party?
    fun partyFromName(name: String): Party?

    fun partyFromAnonymous(party: AnonymousParty): Party?
    fun partyFromAnonymous(partyRef: PartyAndReference) = partyFromAnonymous(partyRef.party)

    /**
     * Get the certificate chain showing an anonymous party is owned by the given party.
     */
    fun pathForAnonymous(anonymousParty: AnonymousParty): CertPath?
}
