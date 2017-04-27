#pragma once

#include <gui/MessageWidget.h>
#include <gui/PINDialog.h>

#include <PCSC/wintypes.h>
#include <PCSC/winscard.h>

#include <QString>
#include <QDebug>

#include <array>
#include <memory>
#include <vector>

class JavaCard {
    template< size_t size >
    using bytes = std::array< BYTE, size >;

    static const bytes< 15 > select_apdu;
    static const bytes< 9 > pin_apdu_template;
    static const bytes< 2 > ok_apdu;
    static const bytes< 4 > get_password_apdu;

    /**
     * @brief The resource_handle class wraps any type of resource
     * and releases it during destruction by the provided deleter.
     */
    template< typename T >
    class resource_handle {
        T _resource = {};
        std::function< void(T) > _del;

        void swap(resource_handle& other) {
            std::swap(_resource, other._resource);
            std::swap(_del, other._del);
        }

    public:
        resource_handle() = default;
        resource_handle(const resource_handle& other) = delete;
        resource_handle& operator=(const resource_handle& other) = delete;

        resource_handle(resource_handle&& other) {
            swap(other);
        }

        resource_handle& operator=(resource_handle&& other) {
            resource_handle tmp;
            tmp.swap(other);
            swap(tmp);
            return *this;
        }

        template< typename Deleter >
        resource_handle(T res, Deleter del)
            : _resource(res)
            , _del(del)
        {}

        ~resource_handle() {
            if (_del) {
                _del(_resource);
            }
        }

        T& operator*() { return _resource; }
        operator bool() const { return _del != nullptr; }
    };

    /**
     * @brief make_handle
     * @param res resource to manage
     * @param del deleter cleaning up the resource
     * @return handle instance
     */
    template< typename T, typename Deleter>
    resource_handle<T> make_handle(T res, Deleter del) {
        return resource_handle<T>(res, del);
    }

    resource_handle< SCARDCONTEXT > m_contextHandle;
    resource_handle< SCARDHANDLE > m_cardHandle;
    SCARD_IO_REQUEST m_ioSendPci = {};

public:
    /**
     * @brief The Result class provides result of interaction with Java Card.
     * Based on the success flag the contained string is an error message or
     * a password.
     */
    class Result {
        const bool m_success = false;
        const QString m_string;
    public:
        Result(bool success, QString string)
            : m_success(success)
            , m_string(string)
        {}
        bool success() const { return m_success; }
        const QString& string() const { return m_string; }
    };

    /**
     * @brief password does all the routines necessary for communication with Java Card.
     * @return Instance of Result class containing error message or password.
     */
    static Result password() {
        // connect to the card
        JavaCard card;
        if (!card.connect()) {
            return {false, "Connection failed"};
        }

        // ask user for the PIN
        PINDialog dialog;
        if (dialog.exec() == QDialog::Rejected) {
            return {false, {}};
        }

        // check length of the PIN
        auto pin = dialog.pin();
        if (pin.length() != 4) {
            return {false, "PIN too short"};
        }

        // transform ASCII characters to bytes
        std::array< unsigned char, 4 > pinBytes;
        std::transform(pin.begin(), pin.end(), pinBytes.begin(),
                       [](const QChar& c){ return c.digitValue(); });

        // authenticate with the PIN
        if (!card.sendPin(pinBytes)) {
            return {false, "Invalid PIN"};
        }

        // request password from the card
        auto pass = card.getPassword();
        if (pass.isEmpty()) {
            return {false, "Password load failed"};
        }

        return {true, pass};
    }

    /**
     * @brief isConnected
     * @return true if the crad is already connected
     */
    bool isConnected() const {
        return m_contextHandle && m_cardHandle;
    }

    /**
     * @brief connect connects to a card
     * @return true if connection was successful
     */
    bool connect() {
        if (isConnected()) {
            return true;
        }

        DWORD dwReaders, dwActiveProtocol, dwRecvLength;
        bytes< 258 > receive_buffer;

        // establish context
        {
            SCARDCONTEXT hContext;
            if (SCARD_S_SUCCESS != SCardEstablishContext(SCARD_SCOPE_SYSTEM,
                                                         nullptr,
                                                         nullptr,
                                                         &hContext))
            {
                return false;
            }
            m_contextHandle = make_handle(hContext, [](SCARDCONTEXT ctx){ SCardReleaseContext(ctx); });

            // reader name
            std::vector< char > readers;
            dwReaders = 0;
            if (SCARD_S_SUCCESS != SCardListReaders(hContext,
                                                    nullptr,
                                                    nullptr,
                                                    &dwReaders))
            {
                return false;
            }
            readers.resize(dwReaders);
            if (SCARD_S_SUCCESS != SCardListReaders(hContext,
                                                    nullptr,
                                                    readers.data(),
                                                    &dwReaders))
            {
                return false;
            }

            // connect
            SCARDHANDLE hCard;
            if (SCARD_S_SUCCESS != SCardConnect(hContext,
                                                readers.data(),
                                                SCARD_SHARE_SHARED,
                                                SCARD_PROTOCOL_T0 | SCARD_PROTOCOL_T1,
                                                &hCard,
                                                &dwActiveProtocol))
            {
                return false;
            }
            m_cardHandle = make_handle(hCard, [](SCARDHANDLE card){ SCardDisconnect(card, SCARD_LEAVE_CARD); });
        }

        switch(dwActiveProtocol)
        {
        case SCARD_PROTOCOL_T0:
            m_ioSendPci = *SCARD_PCI_T0;
            break;

        case SCARD_PROTOCOL_T1:
            m_ioSendPci = *SCARD_PCI_T1;
            break;
        }

        // select applet
        dwRecvLength = receive_buffer.size();
        if (SCARD_S_SUCCESS != SCardTransmit(*m_cardHandle,
                                             &m_ioSendPci,
                                             select_apdu.begin(),
                                             select_apdu.size(),
                                             nullptr,
                                             receive_buffer.begin(),
                                             &dwRecvLength))
        {
            return false;
        }

        return true;
    }

    /**
     * @brief sendPin authenticates with the provided PIN
     * @param pin PIN
     * @return true if PIN is valid
     */
    bool sendPin(const bytes< 4 >& pin) {
        auto pin_apdu = pin_apdu_template;
        std::copy(pin.begin(), pin.end(), std::next(pin_apdu.begin(), 5));

        // send PIN APDU
        bytes< 258 > response;
        auto responseLength = response.size();
        if (SCARD_S_SUCCESS != SCardTransmit(*m_cardHandle,
                           &m_ioSendPci,
                           pin_apdu.begin(),
                           pin_apdu.size(),
                           nullptr,
                           response.begin(),
                           &responseLength))
        {
            return false;
        }

        // check response from the card
        if (responseLength != 2 || !std::equal(ok_apdu.begin(), ok_apdu.end(), response.begin())) {
            return false;
        }

        return true;
    }

    /**
     * @brief getPassword requests password from the card
     * @return password
     */
    QString getPassword() {
        bytes< 258 > response;
        auto responseLength = response.size();
        if (SCARD_S_SUCCESS != SCardTransmit(*m_cardHandle,
                           &m_ioSendPci,
                           get_password_apdu.begin(),
                           get_password_apdu.size(),
                           nullptr,
                           response.begin(),
                           &responseLength))
        {
            return {};
        }

        if (responseLength <= 2 || !std::equal(ok_apdu.begin(), ok_apdu.end(), std::next(response.begin(), responseLength-2))) {
            return {};
        }

        return QString::fromLocal8Bit(reinterpret_cast<const char *>(response.begin()), responseLength-2);
    }
};
