package ru.iriyc.cc.server

class QuoteException(override val message: String) : RuntimeException(message) {
}