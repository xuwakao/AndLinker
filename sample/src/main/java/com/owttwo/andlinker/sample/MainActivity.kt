package com.owttwo.andlinker.sample

import android.graphics.Color
import android.os.Bundle
import android.text.SpannableString
import android.text.Spanned
import android.text.style.ForegroundColorSpan
import android.widget.TextView
import androidx.appcompat.app.AppCompatActivity

class MainActivity : AppCompatActivity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_main)

        val textView = findViewById<TextView>(R.id.sample_text)
        textView.text = colorize(stringFromJNI())
        textView.setOnClickListener {
            textView.text = colorize(stringFromJNI())
        }
    }

    private fun colorize(text: String): SpannableString {
        val spannable = SpannableString(text)
        val green = Color.parseColor("#4CAF50")
        val red = Color.parseColor("#F44336")
        val gray = Color.parseColor("#9E9E9E")

        var index = 0
        while (index < text.length) {
            val lineEnd = text.indexOf('\n', index).let { if (it == -1) text.length else it }

            when {
                text.startsWith("[PASS]", index) -> {
                    spannable.setSpan(
                        ForegroundColorSpan(green), index, lineEnd,
                        Spanned.SPAN_EXCLUSIVE_EXCLUSIVE
                    )
                }
                text.startsWith("[FAIL]", index) -> {
                    spannable.setSpan(
                        ForegroundColorSpan(red), index, lineEnd,
                        Spanned.SPAN_EXCLUSIVE_EXCLUSIVE
                    )
                }
                text.startsWith("---", index) || text.startsWith("===", index) -> {
                    spannable.setSpan(
                        ForegroundColorSpan(gray), index, lineEnd,
                        Spanned.SPAN_EXCLUSIVE_EXCLUSIVE
                    )
                }
            }
            index = lineEnd + 1
        }
        return spannable
    }

    external fun stringFromJNI(): String

    companion object {
        init {
            System.loadLibrary("adl")
            System.loadLibrary("adlhooker")
            System.loadLibrary("sample")
        }
    }
}
