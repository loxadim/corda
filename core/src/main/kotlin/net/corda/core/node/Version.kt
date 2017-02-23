package net.corda.core.node

import java.util.regex.Pattern

data class Version(val major: Int, val minor: Int, val snapshot: Boolean) : Comparable<Version> {
    companion object {
        private val comparator = java.util.Comparator.comparing(Version::major).thenComparing(Version::minor)
        private val pattern = Pattern.compile("""(\d+)\.(\d+)(-SNAPSHOT)?""")

        fun parse(string: String): Version {
            val matcher = pattern.matcher(string)
            require(matcher.matches())
            return Version(matcher.group(1).toInt(), matcher.group(2).toInt(), matcher.group(3) != null)
        }
    }

    override fun compareTo(other: Version): Int {
        require(this.snapshot == other.snapshot) { "SNAPSHOT and non-SNAPSHOT versions are not comparable" }
        return comparator.compare(this, other)
    }

    override fun toString(): String = if (snapshot) "$major.$minor-SNAPSHOT" else "$major.$minor"
}