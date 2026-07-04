package com.hopae.eudi.wallet.sdjwt

class JsonException(message: String) : Exception(message)

/**
 * Minimal JSON model owned by the SDK. Object entries preserve insertion order and
 * the serializer is byte-stable, so both platform cores emit identical payloads —
 * the same cross-language guarantee we pin for CBOR.
 */
sealed class JsonValue {

    object Null : JsonValue() {
        override fun toString() = "null"
    }

    data class Bool(val value: Boolean) : JsonValue()
    data class NumInt(val value: Long) : JsonValue()

    /** Avoid in signed payloads that must be cross-language byte-identical. */
    data class NumDouble(val value: Double) : JsonValue()
    data class Str(val value: String) : JsonValue()
    data class Arr(val items: List<JsonValue>) : JsonValue()

    data class Obj(val entries: List<Pair<String, JsonValue>>) : JsonValue() {
        operator fun get(key: String): JsonValue? = entries.firstOrNull { it.first == key }?.second
    }

    fun serialize(): String = StringBuilder().also { write(it) }.toString()

    private fun write(sb: StringBuilder) {
        when (this) {
            Null -> sb.append("null")
            is Bool -> sb.append(if (value) "true" else "false")
            is NumInt -> sb.append(value.toString())
            is NumDouble -> sb.append(value.toString())
            is Str -> writeString(sb, value)
            is Arr -> {
                sb.append('[')
                items.forEachIndexed { i, v ->
                    if (i > 0) sb.append(',')
                    v.write(sb)
                }
                sb.append(']')
            }
            is Obj -> {
                sb.append('{')
                entries.forEachIndexed { i, (k, v) ->
                    if (i > 0) sb.append(',')
                    writeString(sb, k)
                    sb.append(':')
                    v.write(sb)
                }
                sb.append('}')
            }
        }
    }

    companion object {
        fun parse(text: String): JsonValue = JsonParser(text).parseDocument()

        internal fun writeString(sb: StringBuilder, s: String) {
            sb.append('"')
            for (c in s) {
                when {
                    c == '"' -> sb.append("\\\"")
                    c == '\\' -> sb.append("\\\\")
                    c == '\n' -> sb.append("\\n")
                    c == '\r' -> sb.append("\\r")
                    c == '\t' -> sb.append("\\t")
                    c == '\b' -> sb.append("\\b")
                    c == '\u000C' -> sb.append("\\f")
                    c < ' ' -> sb.append("\\u%04x".format(c.code))
                    else -> sb.append(c)
                }
            }
            sb.append('"')
        }
    }
}

private class JsonParser(private val text: String) {
    private var pos = 0
    private var depth = 0

    fun parseDocument(): JsonValue {
        val v = parseValue()
        skipWs()
        if (pos != text.length) throw JsonException("trailing content at $pos")
        return v
    }

    private fun parseValue(): JsonValue {
        if (++depth > 256) throw JsonException("nesting too deep")
        try {
            skipWs()
            if (pos >= text.length) throw JsonException("unexpected end of input")
            return when (val c = text[pos]) {
                '{' -> parseObject()
                '[' -> parseArray()
                '"' -> JsonValue.Str(parseString())
                't' -> literal("true", JsonValue.Bool(true))
                'f' -> literal("false", JsonValue.Bool(false))
                'n' -> literal("null", JsonValue.Null)
                else -> if (c == '-' || c in '0'..'9') parseNumber() else throw JsonException("unexpected '$c' at $pos")
            }
        } finally {
            depth--
        }
    }

    private fun <T : JsonValue> literal(word: String, value: T): T {
        if (!text.startsWith(word, pos)) throw JsonException("invalid literal at $pos")
        pos += word.length
        return value
    }

    private fun parseObject(): JsonValue.Obj {
        pos++ // {
        val entries = mutableListOf<Pair<String, JsonValue>>()
        skipWs()
        if (peek() == '}') {
            pos++
            return JsonValue.Obj(entries)
        }
        while (true) {
            skipWs()
            if (peek() != '"') throw JsonException("expected object key at $pos")
            val key = parseString()
            skipWs()
            if (peek() != ':') throw JsonException("expected ':' at $pos")
            pos++
            entries.add(key to parseValue())
            skipWs()
            when (peek()) {
                ',' -> pos++
                '}' -> {
                    pos++
                    return JsonValue.Obj(entries)
                }
                else -> throw JsonException("expected ',' or '}' at $pos")
            }
        }
    }

    private fun parseArray(): JsonValue.Arr {
        pos++ // [
        val items = mutableListOf<JsonValue>()
        skipWs()
        if (peek() == ']') {
            pos++
            return JsonValue.Arr(items)
        }
        while (true) {
            items.add(parseValue())
            skipWs()
            when (peek()) {
                ',' -> pos++
                ']' -> {
                    pos++
                    return JsonValue.Arr(items)
                }
                else -> throw JsonException("expected ',' or ']' at $pos")
            }
        }
    }

    private fun parseString(): String {
        pos++ // "
        val sb = StringBuilder()
        while (true) {
            if (pos >= text.length) throw JsonException("unterminated string")
            when (val c = text[pos++]) {
                '"' -> return sb.toString()
                '\\' -> {
                    if (pos >= text.length) throw JsonException("unterminated escape")
                    when (val e = text[pos++]) {
                        '"' -> sb.append('"')
                        '\\' -> sb.append('\\')
                        '/' -> sb.append('/')
                        'n' -> sb.append('\n')
                        'r' -> sb.append('\r')
                        't' -> sb.append('\t')
                        'b' -> sb.append('\b')
                        'f' -> sb.append('\u000C')
                        'u' -> {
                            if (pos + 4 > text.length) throw JsonException("bad \\u escape")
                            sb.append(text.substring(pos, pos + 4).toInt(16).toChar())
                            pos += 4
                        }
                        else -> throw JsonException("invalid escape '\\$e'")
                    }
                }
                else -> {
                    if (c < ' ') throw JsonException("unescaped control character")
                    sb.append(c)
                }
            }
        }
    }

    private fun parseNumber(): JsonValue {
        val start = pos
        if (peek() == '-') pos++
        while (pos < text.length && (text[pos].isDigit() || text[pos] in ".eE+-")) pos++
        val raw = text.substring(start, pos)
        raw.toLongOrNull()?.let { if ('.' !in raw && 'e' !in raw && 'E' !in raw) return JsonValue.NumInt(it) }
        return JsonValue.NumDouble(raw.toDoubleOrNull() ?: throw JsonException("invalid number '$raw'"))
    }

    private fun peek(): Char = if (pos < text.length) text[pos] else throw JsonException("unexpected end of input")

    private fun skipWs() {
        while (pos < text.length && text[pos] in " \t\n\r") pos++
    }
}
