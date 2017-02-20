package net.corda.core.flows

import java.lang.annotation.Inherited
import java.util.*
import net.corda.core.crypto.Party

val versionRegex = Regex("^(\\d+\\.\\d*)$") // Format: Major.Minor

//TODO Do want to have inherited annotation of sublcasses? It makes life easier when testing + defaults, but it's hard to debug when you don't annotate your flow.
/**
 * Annotation used for flow to indicate it's general flow it belongs to (for example, if you have Sender-Receiver classes)
 * that belong to one general flow "SendReceive" - it would be the name of flow, and this name would be registered as
 * flow initiator on the node, also it can be advertised in [NetworkMapService].
 * @param version version of this [FlowLogic] class
 * @param genericName name of the flow that [FlowLogic] belongs to
 * @param preference what versions we accept when negotiating connection
 * @param advertise do we want to advertise this [FlowLogic] in [NetworkMapService]
 */
// Retention is default true at runtime.
@Target(AnnotationTarget.CLASS)
@MustBeDocumented
@Inherited
annotation class FlowVersion(val version: String, val genericName: String, val preference: Array<String>, val advertise: Boolean = true) //TODO min max version
// But... it's highly impossible that we will keep lots of flow versions on the node.

fun majorVersionMatch(version1: String, version2: String): Boolean {
    require(version1.matches(versionRegex) && version2.matches(versionRegex)) { "Incorrect version formats" }
    return (version1.split(".")[0] == version2.split(".")[0])
}

// I needed whole flow metadata stored, later it can be useful with encoding flow backward compatibility etc.
// Problem with flows on our platform is that on incoming connection we can register as an initiator whatever we want.
// With that solution it's easier to hold some data and have control over that process.
// Used if we have more than one flow version on the node, we can specify how it will be advertised.
/**
 * Way of registering multiple versions of [FlowLogic] at once. Also makes specifying of flow metadata much easier.
 * That metadata is later used in [NodeInfo] for advertising purposes.
 * @param preferred version of this general flow
 * @param deprecated other versions we support on the node
 * @param genericFlowName name of the flow that [FlowLogic]s in that set belong to
 * @param toAdvertise do we want to advertise this flows in [NetworkMapService]
 * TODO more documentation
 */
interface FlowFactory {
    val preferred: String // TODO defaults
    val deprecated: Array<String>
    val toAdvertise: Boolean // We may wish not to advertise that flow in NMS but still register it. For example if we want to have private communication between nodes.
    val genericFlowName: String
    fun getFlow(version: String, party: Party): FlowLogic<*>?
}

// Used when registering flow initiators
// TODO Refactor that, can just register advertisedFlows -> make data class for storing that info (for extracting FlowLogic annotations).
class FlowVersionInfo(
        val genericFlowName: String,
        val preferred: String, // With default genericFlowName/ highest version
        val deprecated: Array<String> = emptyArray(),
        val advertise: Boolean = true // Do we want to advertise this flow.
) {
    init {
        require(toFullList().all{ it.matches(versionRegex) }) { "Some of version information doesn't match format: major.minor for flow: $genericFlowName" }
    }

    companion object {
        fun getVersionAnnotation(markerClass: Class<*>): FlowVersionInfo {
            val versionAnn = markerClass.annotations.find { it is FlowVersion } as? FlowVersion // It has to be Class not KClass because otherwise inherited annotations won't be seen.
            versionAnn ?: throw IllegalArgumentException("Flow without version annotation: ${markerClass}")
            val flowVersion = versionAnn.version
            val flowName = if (versionAnn.genericName == "DefaultFlowVersion")
                markerClass.name // TODO
            else versionAnn.genericName
            val preference = versionAnn.preference
            val advertise = versionAnn.advertise
            return FlowVersionInfo(flowName, flowVersion, preference, advertise)
        }
    }

    fun toFullList(): Array<String> {
        return deprecated + preferred
    }

    fun isCompatible(flowVersion: String): Boolean = flowVersion in toFullList() // TODO refactor

    // TODO refactor
    @Throws(IllegalArgumentException::class)
    operator fun plus(other: FlowVersionInfo): FlowVersionInfo {
        val newPreferred = listOf(this.preferred, other.preferred).sorted()
        if (this.genericFlowName == other.genericFlowName)
            return FlowVersionInfo(
                    this.genericFlowName,
                    newPreferred[0],
                    (this.deprecated + other.deprecated + newPreferred[1]).toSet().toTypedArray(),
                    this.advertise && other.advertise //todo advertise
            )
        else
            throw IllegalArgumentException("Cannot merge two different FlowVersionInfo entries.")
    }

    fun toAdvertisedFlows(): AdvertisedFlow? {
        if (advertise)
            return AdvertisedFlow(genericFlowName, preferred, deprecated)
        else return null
    }
}

// Flow versions that will be advertised through NetworkMapService.
data class AdvertisedFlow(
        val genericFlowName: String,
        val preferred: String, // TODO Default highest version.
        val deprecated: Array<String> = emptyArray() // Flows we still support on the node as a new incoming communication.
) {
    init {
        require(toList().all{ it.matches(versionRegex) }) { "Some of version information doesn't match format: major.minor" }
    }

    fun toList(): Array<String> {
        return deprecated + preferred
    }

    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (other?.javaClass != javaClass) return false
        other as AdvertisedFlow
        if (genericFlowName != other.genericFlowName) return false
        if (toList().sorted() != other.toList().sorted()) return false // Force ordering.
        return true
    }

    override fun hashCode(): Int = Objects.hash(genericFlowName, preferred, deprecated.sorted())
}
