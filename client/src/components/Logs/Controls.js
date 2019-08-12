import React, { Fragment } from 'react';
import PropTypes from 'prop-types';
import { Trans, withNamespaces } from 'react-i18next';

const Controls = (props) => {
    const {
        queryLogEnabled,
        logStatusProcessing,
        toggleLogStatus,
        handleDownloadButton,
        getLogs,
        clearLogs,
    } = props;

    if (queryLogEnabled) {
        return (
            <Fragment>
                <button
                    className="btn btn-gray btn-sm mr-2"
                    type="button"
                    onClick={() => toggleLogStatus(queryLogEnabled)}
                    disabled={logStatusProcessing}
                >
                    <Trans>disabled_log_btn</Trans>
                </button>
                <button
                    className="btn btn-primary btn-sm mr-2"
                    type="button"
                    onClick={() => handleDownloadButton()}
                >
                    <Trans>download_log_file_btn</Trans>
                </button>
                <button
                    className="btn btn-outline-danger btn-sm mr-2"
                    type="button"
                    onClick={() => clearLogs()}
                >
                    <Trans>query_log_clear</Trans>
                </button>
                <button
                    className="btn btn-outline-primary btn-sm"
                    type="button"
                    onClick={() => getLogs()}
                >
                    <Trans>refresh_btn</Trans>
                </button>
            </Fragment>
        );
    }

    return (
        <button
            className="btn btn-success btn-sm mr-2"
            type="submit"
            onClick={() => toggleLogStatus(queryLogEnabled)}
            disabled={logStatusProcessing}
        >
            <Trans>enabled_log_btn</Trans>
        </button>
    );
};

Controls.propTypes = {
    queryLogEnabled: PropTypes.bool.isRequired,
    logStatusProcessing: PropTypes.bool.isRequired,
    toggleLogStatus: PropTypes.func.isRequired,
    handleDownloadButton: PropTypes.func.isRequired,
    getLogs: PropTypes.func.isRequired,
    clearLogs: PropTypes.func.isRequired,
};

export default withNamespaces()(Controls);
