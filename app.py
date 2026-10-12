
import streamlit as st

from security import (
    encrypt_data,
    decrypt_data,
    calculate_sha256,
    check_password_strength,
)

st.set_page_config(
    page_title="SecureVault | CNS Toolkit",
    page_icon="🔐",
    layout="wide",
)

# ---------------- PAGE HEADER ----------------

st.title("🔐 SecureVault")
st.subheader("Python-Based Cybersecurity Toolkit")
st.write(
    "A Cryptography & Network Security mini project "
    "for secure file handling, message protection, and integrity checking."
)

st.info(
    "Educational prototype demonstrating AES-GCM encryption, "
    "PBKDF2 key derivation, SHA-256 hashing, and password analysis."
)

# ---------------- DASHBOARD ----------------

tab1, tab2, tab3, tab4 = st.tabs([
    "📁 File Security",
    "💬 Message Encryption",
    "🛡️ File Integrity",
    "🔑 Password Checker",
])

# ==================================================
# TAB 1: FILE ENCRYPTION AND DECRYPTION
# ==================================================

with tab1:
    st.header("File Encryption & Decryption")
    st.write(
        "Encrypt a file with a password or decrypt a SecureVault "
        "encrypted file using the same password."
    )

    encrypt_col, decrypt_col = st.columns(2)

    with encrypt_col:
        st.subheader("🔒 Encrypt a File")

        source_file = st.file_uploader(
            "Choose a file to encrypt",
            key="file_to_encrypt",
        )

        encrypt_password = st.text_input(
            "Create encryption password",
            type="password",
            key="file_encrypt_password",
        )

        if st.button("Encrypt File", key="encrypt_file_button"):
            if source_file is None:
                st.error("Please select a file.")
            elif not encrypt_password:
                st.error("Please enter an encryption password.")
            else:
                try:
                    original_bytes = source_file.getvalue()
                    encrypted_bytes = encrypt_data(
                        original_bytes,
                        encrypt_password,
                    )

                    st.success("File encrypted successfully!")

                    st.download_button(
                        "Download Encrypted File",
                        data=encrypted_bytes,
                        file_name=source_file.name + ".svault",
                        mime="application/octet-stream",
                        key="download_encrypted_file",
                    )

                except Exception:
                    st.error(
                        "Encryption failed. Please check your input "
                        "and try again."
                    )

    with decrypt_col:
        st.subheader("🔓 Decrypt a File")

        encrypted_file = st.file_uploader(
            "Choose a .svault file",
            type=["svault"],
            key="file_to_decrypt",
        )

        decrypt_password = st.text_input(
            "Enter decryption password",
            type="password",
            key="file_decrypt_password",
        )

        if st.button("Decrypt File", key="decrypt_file_button"):
            if encrypted_file is None:
                st.error("Please select an encrypted file.")
            elif not decrypt_password:
                st.error("Please enter the password.")
            else:
                try:
                    decrypted_bytes = decrypt_data(
                        encrypted_file.getvalue(),
                        decrypt_password,
                    )

                    original_name = encrypted_file.name[:-7]
                    if not original_name:
                        original_name = "decrypted_file"

                    st.success("File decrypted and authenticated!")

                    st.download_button(
                        "Download Decrypted File",
                        data=decrypted_bytes,
                        file_name=original_name,
                        mime="application/octet-stream",
                        key="download_decrypted_file",
                    )

                except ValueError:
                    st.error(
                        "Decryption failed. Check the password and file."
                    )
                except Exception:
                    st.error("Unable to process this encrypted file.")

    st.caption(
        "Keep your password safe. If you lose it, the encrypted file "
        "cannot be recovered through this application."
    )

# ==================================================
# TAB 2: MESSAGE ENCRYPTION
# ==================================================

with tab2:
    st.header("Secure Message Encryption")
    st.write("Encrypt a text message or decrypt a SecureVault message.")

    message_mode = st.radio(
        "Choose an operation",
        ["Encrypt Message", "Decrypt Message"],
        horizontal=True,
    )

    if message_mode == "Encrypt Message":
        message = st.text_area(
            "Enter your message",
            placeholder="Type the message you want to protect...",
        )

        message_password = st.text_input(
            "Encryption password",
            type="password",
            key="message_encrypt_password",
        )

        if st.button("Encrypt Message", key="encrypt_message_button"):
            if not message:
                st.warning("Please enter a message.")
            elif not message_password:
                st.warning("Please enter a password.")
            else:
                try:
                    encrypted_message = encrypt_data(
                        message.encode("utf-8"),
                        message_password,
                    )

                    st.success("Message encrypted successfully!")
                    st.text_area(
                        "Encrypted message package",
                        value=encrypted_message.decode("utf-8"),
                        height=180,
                        key="encrypted_message_output",
                    )

                    st.download_button(
                        "Download Encrypted Message",
                        data=encrypted_message,
                        file_name="secure_message.svault",
                        mime="application/octet-stream",
                        key="download_encrypted_message",
                    )

                except Exception:
                    st.error("Message encryption failed.")

    else:
        encrypted_message_input = st.text_area(
            "Paste the complete encrypted message package",
            height=180,
            placeholder='Paste the JSON content from a SecureVault package...',
        )

        message_decrypt_password = st.text_input(
            "Decryption password",
            type="password",
            key="message_decrypt_password",
        )

        if st.button("Decrypt Message", key="decrypt_message_button"):
            if not encrypted_message_input.strip():
                st.warning("Please paste an encrypted message.")
            elif not message_decrypt_password:
                st.warning("Please enter the password.")
            else:
                try:
                    decrypted_message = decrypt_data(
                        encrypted_message_input.encode("utf-8"),
                        message_decrypt_password,
                    )

                    st.success("Message decrypted and authenticated!")
                    st.text_area(
                        "Original message",
                        value=decrypted_message.decode("utf-8"),
                        height=120,
                        key="decrypted_message_output",
                    )

                except Exception:
                    st.error(
                        "Decryption failed. Check the password and "
                        "encrypted message."
                    )

# ==================================================
# TAB 3: FILE INTEGRITY CHECKER
# ==================================================

with tab3:
    st.header("SHA-256 File Integrity Checker")
    st.write(
        "Calculate a file's SHA-256 hash and optionally compare it "
        "with a trusted reference hash."
    )

    integrity_file = st.file_uploader(
        "Choose a file to analyze",
        key="integrity_file",
    )

    reference_hash = st.text_input(
        "Trusted SHA-256 hash (optional)",
        placeholder="Paste a 64-character SHA-256 hash",
    )

    if st.button("Calculate SHA-256", key="calculate_hash_button"):
        if integrity_file is None:
            st.warning("Please select a file.")
        else:
            file_hash = calculate_sha256(integrity_file.getvalue())

            st.success("SHA-256 hash calculated.")
            st.code(file_hash)

            if reference_hash.strip():
                cleaned_reference = reference_hash.strip().lower()

                if (
                    len(cleaned_reference) != 64
                    or any(
                        char not in "0123456789abcdef"
                        for char in cleaned_reference
                    )
                ):
                    st.error(
                        "The reference must be a valid 64-character "
                        "hexadecimal SHA-256 hash."
                    )
                elif file_hash == cleaned_reference:
                    st.success(
                        "MATCH: The file matches the supplied reference hash."
                    )
                else:
                    st.error(
                        "MISMATCH: The file differs from the supplied "
                        "reference hash."
                    )
            else:
                st.info(
                    "Save this hash as a reference if you need to "
                    "check the file again later."
                )

# ==================================================
# TAB 4: PASSWORD STRENGTH CHECKER
# ==================================================

with tab4:
    st.header("Password Strength Checker")
    st.write(
        "Get basic password-strength feedback. Your entered password "
        "is not saved by this checker."
    )

    password_input = st.text_input(
        "Enter a sample password",
        type="password",
        key="strength_password",
    )

    if st.button("Analyze Password", key="analyze_password_button"):
        if not password_input:
            st.warning("Please enter a password.")
        else:
            result = check_password_strength(password_input)

            st.metric("Strength", result["strength"])
            st.progress(result["score"] / 6)

            st.write(
                f"Criteria satisfied: {result['score']} out of 6"
            )

            if result["suggestions"]:
                st.write("Suggestions for improvement:")
                for suggestion in result["suggestions"]:
                    st.write(f"- {suggestion}")
            else:
                st.success(
                    "All basic checks passed. This does not guarantee "
                    "that the password is secure against every attack."
                )

# ---------------- FOOTER ----------------

st.divider()
st.caption(
    "SecureVault | Cryptography & Network Security Mini Project | "
    "Python + Streamlit"
)
