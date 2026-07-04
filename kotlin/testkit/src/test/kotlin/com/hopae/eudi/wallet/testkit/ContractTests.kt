package com.hopae.eudi.wallet.testkit

import kotlinx.coroutines.runBlocking
import kotlin.test.Test

class ContractTests {

    @Test
    fun softwareSecureAreaPassesPortContract() = runBlocking {
        SecureAreaContract.verify(SoftwareSecureArea())
    }

    @Test
    fun inMemoryStorageDriverPassesPortContract() = runBlocking {
        StorageDriverContract.verify(InMemoryStorageDriver())
    }
}
