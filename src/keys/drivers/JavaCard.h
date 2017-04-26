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

    static const unsigned char CLA = 0x80;

    static const bytes< 15 > select_apdu;
    static const bytes< 9 > pin_apdu_template;
    static const bytes< 2 > ok_apdu;
    static const bytes< 4 > get_password_apdu;

    template< typename T >
    class handle {
        T _resource = {};
        std::function< void(T) > _del;

        void swap(handle& other) {
            std::swap(_resource, other._resource);
            std::swap(_del, other._del);
        }

    public:
        handle() = default;
        handle(const handle& other) = delete;
        handle& operator=(const handle& other) = delete;

        handle(handle&& other) {
            swap(other);
        }

        handle& operator=(handle&& other) {
            handle tmp;
            tmp.swap(other);
            swap(tmp);
            return *this;
        }

        template< typename Deleter >
        handle(T res, Deleter del)
            : _resource(res)
            , _del(del)
        {}

        ~handle() {
            if (_del) {
                qDebug() << "Destructing handle";
                _del(_resource);
            }
        }

        T& operator*() { return _resource; }
        operator bool() const { return _del != nullptr; }
    };

    template< typename T, typename Deleter>
    handle<T> make_handle(T res, Deleter del) {
        return handle<T>(res, del);
    }

    handle< SCARDCONTEXT > context_handle;
    handle< SCARDHANDLE > card_handle;

    SCARD_IO_REQUEST pioSendPci = {};

public:
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

    static Result password() {
        JavaCard card;
        if (!card.connect()) {
            return {false, "Connection failed"};
        }

        PINDialog dialog;
        if (dialog.exec() == QDialog::Rejected) {
            return {false, {}};
        }

        auto pin = dialog.pin();
        if (pin.length() != 4) {
            return {false, "PIN too short"};
        }

        std::array< unsigned char, 4 > pinBytes;
        std::transform(pin.begin(), pin.end(), pinBytes.begin(),
                       [](const QChar& c){ return c.digitValue(); });

        if (!card.sendPin(pinBytes)) {
            return {false, "Invalid PIN"};
        }

        auto pass = card.getPassword();
        if (pass.isEmpty()) {
            return {false, "Password load failed"};
        }

        return {true, pass};
    }

    bool isConnected() const {
        return context_handle && card_handle;
    }

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
            context_handle = make_handle(hContext, [](SCARDCONTEXT ctx){ SCardReleaseContext(ctx); });

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
            card_handle = make_handle(hCard, [](SCARDHANDLE card){ SCardDisconnect(card, SCARD_LEAVE_CARD); });
        }

        switch(dwActiveProtocol)
        {
        case SCARD_PROTOCOL_T0:
            pioSendPci = *SCARD_PCI_T0;
            break;

        case SCARD_PROTOCOL_T1:
            pioSendPci = *SCARD_PCI_T1;
            break;
        }

        // select
        dwRecvLength = receive_buffer.size();
        if (SCARD_S_SUCCESS != SCardTransmit(*card_handle,
                                             &pioSendPci,
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

    bool sendPin(const bytes< 4 >& pin) {
        qDebug() << "Sending PIN:" << QByteArray::fromRawData(
                        reinterpret_cast<const char*>(pin.begin()), pin.size()).toHex();
        auto pin_apdu = pin_apdu_template;
        std::copy(pin.begin(), pin.end(), std::next(pin_apdu.begin(), 5));

        qDebug() << "PIN APDU:" << QByteArray::fromRawData(
                        reinterpret_cast<const char*>(pin_apdu.begin()), pin_apdu.size()).toHex();
        // send PIN APDU
        bytes< 258 > response;
        auto responseLength = response.size();
        if (!SCardTransmit(*card_handle,
                           &pioSendPci,
                           pin_apdu.begin(),
                           pin_apdu.size(),
                           nullptr,
                           response.begin(),
                           &responseLength))
        {
            qDebug() << "Sending PIN failed";
            return false;
        }

        qDebug() << "PIN response:" << QByteArray::fromRawData(
                        reinterpret_cast<const char*>(response.begin()), responseLength).toHex();
        if (responseLength != 2 || !std::equal(ok_apdu.begin(), ok_apdu.end(), response.begin())) {
            return false;
        }

        return true;
    }

    QString getPassword() {
        bytes< 258 > response;
        auto responseLength = response.size();
        if (!SCardTransmit(*card_handle,
                           &pioSendPci,
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
