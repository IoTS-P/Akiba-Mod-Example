package org.iotsplab.akiba.module

/**
 * Configuration for [AkibaExample3].
 *
 * @property prefix Only strings starting with this prefix will be counted in the result. The
 *                  default value matches everything (empty string).
 * @property minLength Minimum length (after trimming) for a string to be counted.
 */
data class AkibaExample3Config(
    val prefix: String = "",
    val minLength: Int = 0,
)
