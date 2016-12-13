package net.corda.node.services.vault
import net.corda.core.flows.FlowLogic
import net.corda.core.flows.StateMachineRunId
import net.corda.core.node.services.VaultService
import net.corda.core.utilities.loggerFor
import net.corda.node.services.statemachine.StateMachineManager
import net.corda.node.utilities.AddOrRemove

class VaultSoftLockManager(val vault: VaultService, smm: StateMachineManager) {

    private companion object {
        val log = loggerFor<VaultSoftLockManager>()
    }

    init {
        smm.changes.subscribe { change ->
            when (change.addOrRemove) {
                AddOrRemove.ADD -> registerSoftLock(change.id, change.logic)
                AddOrRemove.REMOVE -> unregisterSoftLock(change.id, change.logic)
            }
        }
    }

    private fun registerSoftLock(id: StateMachineRunId, logic: FlowLogic<*>) {
        val flowClassName = logic.javaClass.simpleName
        log.info("Reserving soft lock for flow ${flowClassName} with state manager id ${id.uuid}")
        vault.softLockReserve(id.uuid, emptySet())
    }

    private fun  unregisterSoftLock(id: StateMachineRunId, logic: FlowLogic<*>) {
        val flowClassName = logic.javaClass.simpleName
        log.info("Releasing soft lock for flow ${flowClassName} with state manager id ${id.uuid}")
        vault.softLockRelease(id.uuid)

    }
}